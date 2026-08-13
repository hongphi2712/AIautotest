use api_tester_domain::HttpFlow;
use api_tester_ports::{CaptureSink, PortError};
use async_trait::async_trait;

use crate::buffer::SharedFlowBuffer;

/// Adapter that implements the `CaptureSink` port over a `FlowBuffer`.
///
/// The proxy uses a `Block`-policy buffer (from validated config), so pushing
/// never overflows; duplicates are intentionally dropped by deduplication and
/// are not reported as errors.
pub struct FlowBufferSink {
    buffer: SharedFlowBuffer,
}

impl FlowBufferSink {
    pub fn new(buffer: SharedFlowBuffer) -> Self {
        Self { buffer }
    }
}

#[async_trait]
impl CaptureSink for FlowBufferSink {
    async fn push(&self, flow: HttpFlow) -> Result<(), PortError> {
        let _ = self.buffer.push(flow).await;
        Ok(())
    }
}
