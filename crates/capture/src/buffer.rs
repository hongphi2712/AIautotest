use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use api_tester_domain::HttpFlow;
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    Block,
    DropOldest,
    FailFast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Accepted,
    Duplicate,
    Overflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferStats {
    pub capacity: usize,
    pub len: usize,
    pub queued_bytes: usize,
    pub max_bytes: usize,
    pub accepted: u64,
    pub duplicates: u64,
    pub dropped: u64,
    pub dedup_len: usize,
}

pub struct FlowBuffer {
    queue: Mutex<VecDeque<HttpFlow>>,
    capacity: usize,
    queued_bytes: AtomicUsize,
    max_bytes: usize,
    dedup: Mutex<HashSet<String>>,
    dedup_enabled: bool,
    dedup_limit: usize,
    policy: OverflowPolicy,
    closed: AtomicBool,
    notify: Notify,
    accepted: AtomicU64,
    duplicates: AtomicU64,
    dropped: AtomicU64,
}

impl FlowBuffer {
    pub fn new(capacity: usize, dedup_enabled: bool, policy: OverflowPolicy) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            queued_bytes: AtomicUsize::new(0),
            max_bytes: 0,
            dedup: Mutex::new(HashSet::new()),
            dedup_enabled,
            dedup_limit: 100_000,
            policy,
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            accepted: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Caps the buffered payload by approximate bytes. Zero disables the cap.
    /// Under `Block` and `DropOldest` policies a single flow larger than the
    /// cap is still accepted when the queue is empty so that progress is
    /// always possible.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Bounds the deduplication fingerprint set. When the set exceeds this
    /// limit it is cleared, bounding memory growth for long-running captures.
    pub fn with_dedup_limit(mut self, dedup_limit: usize) -> Self {
        self.dedup_limit = dedup_limit;
        self
    }

    /// Builds a capture buffer from validated configuration. Uses `Block`
    /// overflow so producers experience backpressure instead of silent loss.
    pub fn from_config(config: &api_tester_domain::BufferConfig) -> Self {
        Self::new(config.max_size, config.dedup_enabled, OverflowPolicy::Block)
            .with_max_bytes(config.max_bytes)
            .with_dedup_limit(config.dedup_limit)
    }

    pub fn reset_dedup(&self) {
        if self.dedup_enabled {
            self.dedup
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clear();
        }
    }

    pub fn dedup_len(&self) -> usize {
        self.dedup
            .lock()
            .map(|seen| seen.len())
            .unwrap_or_else(|poison| poison.into_inner().len())
    }

    pub async fn push(&self, flow: HttpFlow) -> PushOutcome {
        loop {
            if self.closed.load(Ordering::Acquire) {
                return PushOutcome::Overflow;
            }

            if self.dedup_enabled {
                let fingerprint = flow.fingerprint();
                let mut seen = self
                    .dedup
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                if !seen.insert(fingerprint) {
                    self.duplicates.fetch_add(1, Ordering::Relaxed);
                    return PushOutcome::Duplicate;
                }
                if self.dedup_limit > 0 && seen.len() > self.dedup_limit {
                    seen.clear();
                }
            }

            let incoming_bytes = flow.size_bytes();
            let mut should_wait = false;
            {
                let mut queue = self
                    .queue
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());

                if !self.fits(queue.len(), incoming_bytes) {
                    match self.policy {
                        OverflowPolicy::DropOldest => {
                            while !queue.is_empty() && !self.fits(queue.len(), incoming_bytes) {
                                if let Some(evicted) = queue.pop_front() {
                                    self.queued_bytes
                                        .fetch_sub(evicted.size_bytes(), Ordering::Relaxed);
                                    self.dropped.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        OverflowPolicy::FailFast => {
                            self.dropped.fetch_add(1, Ordering::Relaxed);
                            return PushOutcome::Overflow;
                        }
                        OverflowPolicy::Block => {
                            should_wait = true;
                        }
                    }
                }

                if !should_wait {
                    queue.push_back(flow);
                    self.queued_bytes
                        .fetch_add(incoming_bytes, Ordering::Relaxed);
                    self.accepted.fetch_add(1, Ordering::Relaxed);
                    self.notify.notify_one();
                    return PushOutcome::Accepted;
                }
            }

            let notified = self.notify.notified();
            notified.await;
        }
    }

    fn fits(&self, queue_len: usize, incoming_bytes: usize) -> bool {
        if queue_len >= self.capacity {
            return false;
        }
        self.max_bytes == 0
            || self
                .queued_bytes
                .load(Ordering::Relaxed)
                .saturating_add(incoming_bytes)
                <= self.max_bytes
    }

    pub async fn recv(&self) -> Option<HttpFlow> {
        loop {
            let notified = self.notify.notified();
            {
                let mut queue = self
                    .queue
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                if let Some(flow) = queue.pop_front() {
                    self.queued_bytes
                        .fetch_sub(flow.size_bytes(), Ordering::Relaxed);
                    drop(queue);
                    self.notify.notify_one();
                    return Some(flow);
                }
                if self.closed.load(Ordering::Acquire) {
                    return None;
                }
            }
            notified.await;
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn stats(&self) -> BufferStats {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dedup_len = self.dedup_len();
        BufferStats {
            capacity: self.capacity,
            len: queue.len(),
            queued_bytes: self.queued_bytes.load(Ordering::Relaxed),
            max_bytes: self.max_bytes,
            accepted: self.accepted.load(Ordering::Relaxed),
            duplicates: self.duplicates.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            dedup_len,
        }
    }
}

pub type SharedFlowBuffer = Arc<FlowBuffer>;

#[cfg(test)]
mod tests {
    use super::{FlowBuffer, OverflowPolicy, PushOutcome};
    use api_tester_domain::{HttpFlow, HttpMethod};

    fn flow(seed: u64) -> HttpFlow {
        HttpFlow::new(HttpMethod::Get, "example.com", format!("/api/{seed}"))
    }

    #[tokio::test]
    async fn fail_fast_overflows_when_full() {
        let buffer = FlowBuffer::new(2, false, OverflowPolicy::FailFast);
        assert_eq!(buffer.push(flow(1)).await, PushOutcome::Accepted);
        assert_eq!(buffer.push(flow(2)).await, PushOutcome::Accepted);
        assert_eq!(buffer.push(flow(3)).await, PushOutcome::Overflow);
        assert_eq!(buffer.stats().dropped, 1);
    }

    #[tokio::test]
    async fn drop_oldest_evicts_head_when_full() {
        let buffer = FlowBuffer::new(3, false, OverflowPolicy::DropOldest);
        for seed in 1..=5 {
            assert_eq!(buffer.push(flow(seed)).await, PushOutcome::Accepted);
        }
        let stats = buffer.stats();
        assert_eq!(stats.len, 3);
        assert_eq!(stats.accepted, 5);
        assert_eq!(stats.dropped, 2);
    }

    #[tokio::test]
    async fn block_policy_backpressures_producer() {
        let buffer = std::sync::Arc::new(FlowBuffer::new(1, false, OverflowPolicy::Block));
        let first_flow = flow(1);
        let second_flow = flow(2);
        assert_eq!(buffer.push(first_flow.clone()).await, PushOutcome::Accepted);

        let producer_buffer = buffer.clone();
        let producer = tokio::spawn(async move {
            let start = std::time::Instant::now();
            assert_eq!(
                producer_buffer.push(second_flow).await,
                PushOutcome::Accepted
            );
            start.elapsed()
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(buffer.stats().len, 1);

        assert_eq!(buffer.recv().await, Some(first_flow));
        let elapsed = producer.await.unwrap();
        assert!(
            elapsed >= std::time::Duration::from_millis(50),
            "producer should have been blocked"
        );
    }

    #[tokio::test]
    async fn dedup_drops_duplicates() {
        let buffer = FlowBuffer::new(16, true, OverflowPolicy::FailFast);
        let first = flow(7);
        let duplicate = first.clone();
        assert_eq!(buffer.push(first).await, PushOutcome::Accepted);
        assert_eq!(buffer.push(duplicate).await, PushOutcome::Duplicate);
        assert_eq!(buffer.stats().duplicates, 1);
    }

    #[tokio::test]
    async fn dedup_set_is_bounded_by_limit() {
        let buffer = FlowBuffer::new(16, true, OverflowPolicy::FailFast).with_dedup_limit(5);
        for seed in 0..20 {
            buffer.push(flow(seed)).await;
        }
        assert!(buffer.stats().dedup_len <= 5, "dedup set must stay bounded");
    }

    #[tokio::test]
    async fn reset_dedup_accepts_previously_seen_flow() {
        let buffer = FlowBuffer::new(16, true, OverflowPolicy::FailFast);
        let first = flow(1);
        let duplicate = first.clone();
        assert_eq!(buffer.push(first.clone()).await, PushOutcome::Accepted);
        assert_eq!(buffer.push(duplicate.clone()).await, PushOutcome::Duplicate);

        buffer.reset_dedup();

        assert_eq!(buffer.push(duplicate).await, PushOutcome::Accepted);
        assert_eq!(buffer.stats().dedup_len, 1);
    }

    fn big_flow(seed: u64, body_size: usize) -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Get, "example.com", format!("/big/{seed}"));
        flow.response_body = Some("x".repeat(body_size));
        flow
    }
    #[tokio::test]
    async fn byte_cap_evicts_oldest_until_fits() {
        let buffer = FlowBuffer::new(16, false, OverflowPolicy::DropOldest).with_max_bytes(1_200);

        assert_eq!(buffer.push(big_flow(1, 300)).await, PushOutcome::Accepted);
        assert_eq!(buffer.push(big_flow(2, 300)).await, PushOutcome::Accepted);

        let stats_before = buffer.stats();
        assert_eq!(stats_before.len, 2);
        assert!(stats_before.queued_bytes <= 1_200);

        // Third flow pushes bytes over the cap; the oldest is evicted.
        assert_eq!(buffer.push(big_flow(3, 300)).await, PushOutcome::Accepted);

        let stats = buffer.stats();
        assert_eq!(stats.len, 2);
        assert_eq!(stats.dropped, 1);
        assert!(stats.queued_bytes <= 1_200);
    }
    #[tokio::test]
    async fn oversized_single_flow_is_still_accepted_when_empty() {
        let buffer = FlowBuffer::new(16, false, OverflowPolicy::DropOldest).with_max_bytes(100);

        assert_eq!(buffer.push(big_flow(1, 2_000)).await, PushOutcome::Accepted);
        assert_eq!(buffer.stats().len, 1);
    }

    #[test]
    fn from_config_wires_limits() {
        let config = api_tester_domain::BufferConfig {
            max_size: 64,
            dedup_enabled: true,
            max_bytes: 4_096,
            dedup_limit: 32,
        };
        let buffer = FlowBuffer::from_config(&config);
        let stats = buffer.stats();
        assert_eq!(stats.capacity, 64);
        assert_eq!(stats.max_bytes, 4_096);
        assert_eq!(buffer.dedup_len(), 0);
    }

    #[tokio::test]
    async fn close_flushes_remaining_items() {
        let buffer = std::sync::Arc::new(FlowBuffer::new(16, false, OverflowPolicy::FailFast));
        let first_flow = flow(1);
        let second_flow = flow(2);
        let rejected_flow = flow(3);
        buffer.push(first_flow.clone()).await;
        buffer.push(second_flow.clone()).await;
        buffer.close();
        assert_eq!(buffer.recv().await, Some(first_flow));
        assert_eq!(buffer.recv().await, Some(second_flow));
        assert_eq!(buffer.recv().await, None);
        assert_eq!(buffer.push(rejected_flow).await, PushOutcome::Overflow);
    }
}
