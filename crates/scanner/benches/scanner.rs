use std::sync::Arc;

use api_tester_domain::{HttpFlow, HttpMethod, ScanJob, ScopeConfig};
use api_tester_ports::{HttpClient, HttpRequest, HttpResponse, PortError};
use api_tester_scanner::{
    BuiltinPayloadSource, MutationEngine, PayloadSource, Replayer, RequestExecutor,
    ResponseVerifier, ScanScheduler,
};
use async_trait::async_trait;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tokio_util::sync::CancellationToken;

struct NoopHttpClient;

#[async_trait]
impl HttpClient for NoopHttpClient {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"ok":true}"#.to_vec(),
        })
    }
}

const FLOWS: usize = 50;
const MUTATIONS_PER_FLOW: usize = 12;

fn build_flows(count: usize) -> Vec<HttpFlow> {
    (0..count)
        .map(|index| {
            let mut flow = HttpFlow::new(
                HttpMethod::Get,
                "127.0.0.1",
                format!("/api/resource/{index}"),
            );
            flow.full_url = format!("http://127.0.0.1/api/resource/{index}?q=value&id={index}");
            flow.response_status = 200;
            flow
        })
        .collect()
}

fn build_scheduler(client: Arc<dyn HttpClient>) -> Arc<ScanScheduler> {
    let source: Arc<dyn PayloadSource> = Arc::new(BuiltinPayloadSource);
    let mutation = Arc::new(MutationEngine::new(source, 20));
    let executor = Arc::new(RequestExecutor::new(client, 0, 30));
    let verifier = Arc::new(ResponseVerifier);
    Arc::new(ScanScheduler::new(executor, mutation, verifier))
}

fn make_job() -> ScanJob {
    let mut job = ScanJob::new(1_000_000, 8).unwrap();
    job.config.scope = ScopeConfig {
        include_hosts: vec![r"127\.0\.0\.1".to_owned()],
        ..ScopeConfig::default()
    };
    job.config.enabled_skills = vec!["sqli".to_owned()];
    job.seed = Some(42);
    job
}

async fn run_scan(scheduler: &ScanScheduler, flows: &[HttpFlow], job: &ScanJob) -> usize {
    let result = scheduler
        .run(flows, job, CancellationToken::new())
        .await
        .unwrap();
    result.requests_sent as usize
}

fn bench_mutation_throughput(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let scheduler = build_scheduler(Arc::new(NoopHttpClient));
    let flows = build_flows(FLOWS);
    let job = make_job();

    let mut group = c.benchmark_group("scanner/mutation_throughput");
    group.throughput(Throughput::Elements((FLOWS * MUTATIONS_PER_FLOW) as u64));
    group.bench_function("50_flows_sqli", |b| {
        b.iter(|| runtime.block_on(run_scan(&scheduler, &flows, &job)));
    });
    group.finish();
}

fn bench_replay_latency(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let executor = Arc::new(RequestExecutor::new(Arc::new(NoopHttpClient), 0, 30));
    let replayer = Replayer::new(executor, None);
    let flows = build_flows(200);

    let mut group = c.benchmark_group("scanner/replay_latency");
    group.throughput(Throughput::Elements(200));
    group.bench_function("200_flows", |b| {
        b.iter(|| runtime.block_on(replayer.replay(flows.clone())));
    });
    group.finish();
}

criterion_group!(benches, bench_mutation_throughput, bench_replay_latency);
criterion_main!(benches);
