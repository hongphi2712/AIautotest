use std::sync::Arc;

use api_tester_capture::{FlowBuffer, FlowBufferSink, OverflowPolicy};
use api_tester_domain::{HttpFlow, HttpMethod};
use api_tester_ports::CaptureSink;

#[tokio::test]
async fn sink_pushes_flow_into_buffer() {
    let buffer = Arc::new(FlowBuffer::new(16, false, OverflowPolicy::FailFast));
    let sink = FlowBufferSink::new(buffer.clone());
    let flow = HttpFlow::new(HttpMethod::Get, "example.com", "/api/sink");

    sink.push(flow).await.unwrap();

    assert_eq!(buffer.stats().len, 1);
    assert_eq!(buffer.stats().accepted, 1);
}

#[tokio::test]
async fn sink_reports_duplicate_as_success() {
    let buffer = Arc::new(FlowBuffer::new(16, true, OverflowPolicy::FailFast));
    let sink = FlowBufferSink::new(buffer.clone());
    let first = HttpFlow::new(HttpMethod::Post, "example.com", "/login");
    let duplicate = first.clone();

    sink.push(first).await.unwrap();
    sink.push(duplicate).await.unwrap();

    assert_eq!(buffer.stats().accepted, 1);
    assert_eq!(buffer.stats().duplicates, 1);
}
