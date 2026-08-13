use std::sync::Arc;
use std::time::Duration;

use api_tester_domain::{DomainEvent, HttpFlow};
use api_tester_ports::{EventPublisher, FlowRepository, PortError};

use crate::buffer::SharedFlowBuffer;
use crate::error::CaptureError;

const DEFAULT_MAX_RETRIES: u32 = 3;
const RETRY_BASE_DELAY_MS: u64 = 50;

pub struct PersistenceWriter {
    buffer: SharedFlowBuffer,
    repository: Arc<dyn FlowRepository>,
    event_publisher: Arc<dyn EventPublisher>,
    batch_size: usize,
    max_retries: u32,
}

impl PersistenceWriter {
    pub fn new(
        buffer: SharedFlowBuffer,
        repository: Arc<dyn FlowRepository>,
        event_publisher: Arc<dyn EventPublisher>,
    ) -> Self {
        Self {
            buffer,
            repository,
            event_publisher,
            batch_size: 100,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub async fn run(self) -> Result<(), CaptureError> {
        let mut batch = Vec::with_capacity(self.batch_size);
        loop {
            match self.buffer.recv().await {
                Some(flow) => {
                    batch.push(flow);
                    if batch.len() >= self.batch_size {
                        self.flush(&mut batch).await?;
                    }
                }
                None => {
                    self.flush(&mut batch).await?;
                    return Ok(());
                }
            }
        }
    }

    async fn flush(&self, batch: &mut Vec<HttpFlow>) -> Result<(), CaptureError> {
        if batch.is_empty() {
            return Ok(());
        }
        let flows = std::mem::take(batch);
        self.save_batch_with_retry(&flows).await?;
        for flow in &flows {
            self.event_publisher
                .publish(DomainEvent::flow_captured(flow))
                .await?;
        }
        Ok(())
    }

    async fn save_batch_with_retry(&self, flows: &[HttpFlow]) -> Result<(), CaptureError> {
        let mut attempt = 0u32;
        loop {
            match self.repository.save_batch(flows).await {
                Ok(()) => return Ok(()),
                Err(PortError::Transient(_)) if attempt < self.max_retries => {
                    attempt += 1;
                    let delay = Duration::from_millis(RETRY_BASE_DELAY_MS << attempt);
                    tokio::time::sleep(delay).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}
