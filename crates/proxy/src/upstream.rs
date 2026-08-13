use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use api_tester_domain::ProxyConfig;

use crate::error::ProxyError;

type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;
pub type UpstreamRequest = Request<Full<Bytes>>;

/// Pooled upstream HTTP/HTTPS client. Uses one `hyper` client instance so
/// keep-alive connections are reused across requests. When
/// `upstream_verify_tls` is disabled (the default, required for HTTPS
/// interception) upstream certificates are not verified.
pub struct UpstreamClient {
    client: Client<HttpsConnector, Full<Bytes>>,
}

impl UpstreamClient {
    pub fn new(config: &ProxyConfig) -> Result<Self, ProxyError> {
        let tls_config = build_client_config(config.upstream_verify_tls)?;
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { client })
    }

    pub async fn send(&self, request: UpstreamRequest) -> Result<Response<Incoming>, ProxyError> {
        self.client
            .request(request)
            .await
            .map_err(|error| ProxyError::Upstream(error.to_string()))
    }
}

fn build_client_config(verify_tls: bool) -> Result<ClientConfig, ProxyError> {
    let mut roots = RootCertStore::empty();
    if verify_tls {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !verify_tls {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAllVerifier));
    }
    Ok(config)
}

#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
