use std::sync::Arc;

use api_tester_domain::{AppConfig, HttpFlow};
use api_tester_ports::{CaptureSink, PortError, SessionRepository};
use api_tester_proxy::{
    CertProvider, MatchReplaceEngine, ProxyServer, RcgenCertProvider, ScopeFilter, UpstreamClient,
};
use api_tester_storage::SqliteStore;
use async_trait::async_trait;

struct NoopSink;

#[async_trait]
impl CaptureSink for NoopSink {
    async fn push(&self, _flow: HttpFlow) -> Result<(), PortError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let config = AppConfig::default();
    let scope = Arc::new(ScopeFilter::new(config.scope.clone()).unwrap());
    let mr = Arc::new(MatchReplaceEngine::new(config.match_replace_rules.clone()));
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let cert_dir = std::path::PathBuf::from(&home).join(".api-tester/certs");
    std::fs::create_dir_all(&cert_dir).unwrap();
    let cert: Arc<dyn CertProvider> = Arc::new(RcgenCertProvider::new(cert_dir));
    cert.ca_cert_pem().unwrap();
    let upstream = Arc::new(UpstreamClient::new(&config.proxy).unwrap());
    let sink: Arc<dyn CaptureSink> = Arc::new(NoopSink);
    let store = SqliteStore::open(":memory:").await.unwrap();
    let sessions: Arc<dyn SessionRepository> = Arc::new(store.sessions().clone());
    let proxy = Arc::new(ProxyServer::new(
        config.proxy.clone(),
        scope,
        mr,
        cert,
        upstream,
        sink,
        sessions,
    ));
    proxy.clone().start().await.unwrap();
    println!("proxy listening on {}", proxy.local_addr().await.unwrap());
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
}
