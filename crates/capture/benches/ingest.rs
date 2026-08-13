use std::sync::Arc;

use api_tester_capture::{FlowBuffer, OverflowPolicy};
use api_tester_domain::{HttpFlow, HttpMethod};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_ingest(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    c.bench_function("buffer_push_drain_10k", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                let buffer = Arc::new(FlowBuffer::new(1024, false, OverflowPolicy::Block));
                let producer_buffer = buffer.clone();
                let producer = tokio::spawn(async move {
                    for seed in 0..10_000 {
                        let flow =
                            HttpFlow::new(HttpMethod::Get, "example.com", format!("/api/{seed}"));
                        producer_buffer.push(flow).await;
                    }
                });

                let mut drained = 0usize;
                while drained < 10_000 {
                    if buffer.recv().await.is_some() {
                        drained += 1;
                    }
                }
                producer.await.unwrap();
            });
        });
    });
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);
