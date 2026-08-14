use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_tester_analysis::ParamAnalyzer;
use api_tester_domain::{Finding, HttpFlow, ScanJob};
use rand::SeedableRng;
use rand::seq::SliceRandom;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::budget::BudgetTracker;
use crate::dedup::RequestDedup;
use crate::error::ScanError;
use crate::mutation_engine::{Mutation, MutationEngine};
use crate::rate_limit::HostRateLimiter;
use crate::request_executor::RequestExecutor;
use crate::response_verifier::ResponseVerifier;
use crate::scope_guard::{ScopeGuard, require_allowlist};

/// Why a scan stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    Completed,
    Cancelled,
    BudgetExhausted,
    DurationExceeded,
    ScopeViolation,
}

/// Result of one scan run.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub requests_sent: u64,
    pub stop_reason: StopReason,
    pub mutations_planned: usize,
}

struct Shared {
    budget: BudgetTracker,
    dedup: RequestDedup,
    limiter: Option<HostRateLimiter>,
    requests_sent: AtomicU64,
    findings: Mutex<Vec<Finding>>,
    stop: Mutex<StopReason>,
}

impl Shared {
    fn set_stop(&self, reason: StopReason) {
        let mut stop = self
            .stop
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if matches!(*stop, StopReason::Completed) {
            *stop = reason;
        }
    }
}

/// The async scan engine: plans mutations from flows, then executes them with
/// per-host concurrency, rate limits, budgets, cancellation and dedup. The
/// scope guard is built from the job's own scope config at run time.
pub struct ScanScheduler {
    executor: Arc<RequestExecutor>,
    mutation: Arc<MutationEngine>,
    verifier: Arc<ResponseVerifier>,
}

impl ScanScheduler {
    pub fn new(
        executor: Arc<RequestExecutor>,
        mutation: Arc<MutationEngine>,
        verifier: Arc<ResponseVerifier>,
    ) -> Self {
        Self {
            executor,
            mutation,
            verifier,
        }
    }

    pub async fn run(
        &self,
        flows: &[HttpFlow],
        job: &ScanJob,
        cancel: CancellationToken,
    ) -> Result<ScanResult, ScanError> {
        let config = &job.config;
        require_allowlist(&config.scope)?;
        let scope_filter = api_tester_domain::ScopeFilter::new(config.scope.clone())
            .map_err(|error| ScanError::InvalidScope(error.to_string()))?;
        let guard = Arc::new(ScopeGuard::new(scope_filter));

        let planned = self.plan(flows, job);
        let planned_count = planned.len();
        if config.dry_run {
            return Ok(ScanResult {
                findings: Vec::new(),
                requests_sent: 0,
                stop_reason: StopReason::Completed,
                mutations_planned: planned_count,
            });
        }

        let shared = Arc::new(Shared {
            budget: BudgetTracker::new(
                job.request_budget,
                config.duration_budget_secs.map(Duration::from_secs),
            ),
            dedup: RequestDedup::new(config.dedup_enabled),
            limiter: HostRateLimiter::new(config.per_host_requests_per_sec),
            requests_sent: AtomicU64::new(0),
            findings: Mutex::new(Vec::new()),
            stop: Mutex::new(StopReason::Completed),
        });

        let ordered = order_mutations(planned, job.seed);
        let concurrency = usize::try_from(job.max_concurrency.max(1)).unwrap_or(1);
        let cursor = Arc::new(AtomicUsize::new(0));
        let mutations = Arc::new(ordered);

        let mut workers = Vec::new();
        for _ in 0..concurrency {
            let worker = tokio::spawn(worker_loop(
                mutations.clone(),
                cursor.clone(),
                self.executor.clone(),
                guard.clone(),
                self.verifier.clone(),
                shared.clone(),
                cancel.clone(),
            ));
            workers.push(worker);
        }

        for worker in workers {
            let _ = worker.await;
        }

        let mut findings = shared
            .findings
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        findings.sort_by(|left, right| {
            left.skill_name
                .cmp(&right.skill_name)
                .then(left.title.cmp(&right.title))
                .then(left.payload_value.cmp(&right.payload_value))
        });

        let stop_reason = *shared
            .stop
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        Ok(ScanResult {
            findings,
            requests_sent: shared.requests_sent.load(Ordering::Relaxed),
            stop_reason,
            mutations_planned: planned_count,
        })
    }

    fn plan(&self, flows: &[HttpFlow], job: &ScanJob) -> Vec<Mutation> {
        let analyzer = ParamAnalyzer::new();
        let mut out = Vec::new();
        for flow in flows {
            let params = analyzer.analyze_flow(flow);
            if params.is_empty() {
                continue;
            }
            out.extend(
                self.mutation
                    .mutations_for(flow, &params, &job.config.enabled_skills),
            );
        }
        out
    }
}

/// Deterministic ordering: a stable base sort, then an optional seed-driven
/// shuffle so the same seed always produces the same execution order.
fn order_mutations(mutations: Vec<Mutation>, seed: Option<u64>) -> Vec<Mutation> {
    let mut sorted = mutations;
    sorted.sort_by(|left, right| {
        left.request
            .url
            .cmp(&right.request.url)
            .then(left.payload.param_name.cmp(&right.payload.param_name))
            .then(left.payload.value.cmp(&right.payload.value))
    });
    if let Some(seed) = seed {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        sorted.shuffle(&mut rng);
    }
    sorted
}

async fn worker_loop(
    mutations: Arc<Vec<Mutation>>,
    cursor: Arc<AtomicUsize>,
    executor: Arc<RequestExecutor>,
    guard: Arc<ScopeGuard>,
    verifier: Arc<ResponseVerifier>,
    shared: Arc<Shared>,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            shared.set_stop(StopReason::Cancelled);
            return;
        }
        let index = cursor.fetch_add(1, Ordering::SeqCst);
        let Some(mutation) = mutations.get(index) else {
            return;
        };

        let (host, path) = host_path(&mutation.request.url);
        if !guard.check(&host, &path) {
            shared.set_stop(StopReason::ScopeViolation);
            return;
        }
        if !shared.budget.try_take() {
            shared.set_stop(if shared.budget.time_exceeded() {
                StopReason::DurationExceeded
            } else {
                StopReason::BudgetExhausted
            });
            return;
        }
        if !shared.dedup.first_seen(&mutation.request) {
            continue;
        }
        if let Some(limiter) = &shared.limiter {
            limiter.until_ready(&host).await;
        }
        shared.requests_sent.fetch_add(1, Ordering::Relaxed);
        if let Ok(response) = executor.execute(mutation.request.clone()).await {
            if let Some(finding) = verifier.verify(mutation, &response) {
                shared
                    .findings
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(finding);
            }
        }
    }
}

fn host_path(url_str: &str) -> (String, String) {
    if let Ok(url) = Url::parse(url_str) {
        return (
            url.host_str().unwrap_or_default().to_owned(),
            url.path().to_owned(),
        );
    }
    match url_str.split_once('/') {
        Some((host, path)) => (host.to_owned(), format!("/{path}")),
        None => (url_str.to_owned(), "/".to_owned()),
    }
}
