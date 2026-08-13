use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::ProxyError;

/// A generated certificate bundle for one host, ready to build a rustls
/// server configuration for MITM TLS interception.
pub struct HostCert {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl HostCert {
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self, ProxyError> {
        let cert = CertificateDer::from_pem_file(cert_path).map_err(cert_error)?;
        let key = PrivateKeyDer::from_pem_file(key_path).map_err(cert_error)?;
        Ok(Self {
            cert_chain: vec![cert],
            private_key: key,
        })
    }

    fn from_generated(cert: &Certificate, key: &KeyPair) -> Result<Self, ProxyError> {
        let private_key =
            PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).map_err(cert_error)?;
        Ok(Self {
            cert_chain: vec![cert.der().clone()],
            private_key,
        })
    }

    pub fn server_config(&self) -> Result<ServerConfig, ProxyError> {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert_chain.clone(), self.private_key.clone_key())
            .map_err(|error| ProxyError::Cert(error.to_string()))
    }
}

/// Provides per-host certificates for HTTPS interception.
pub trait CertProvider: Send + Sync {
    fn host_cert(&self, hostname: &str) -> Result<HostCert, ProxyError>;
    fn ca_cert_pem(&self) -> Result<String, ProxyError>;
}

struct CaMaterial {
    cert: Certificate,
    key: KeyPair,
    original_pem: String,
}

/// Certificate authority + per-host certificate generation, cached on disk.
/// Mirrors the Python `CertManager`: CA reused across restarts, host certs
/// generated once per host and cached.
pub struct RcgenCertProvider {
    cert_dir: PathBuf,
    ca: Mutex<Option<Arc<CaMaterial>>>,
}

impl RcgenCertProvider {
    pub fn new(cert_dir: PathBuf) -> Self {
        Self {
            cert_dir,
            ca: Mutex::new(None),
        }
    }

    fn ca(&self) -> Result<Arc<CaMaterial>, ProxyError> {
        let mut guard = self.ca.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(ca) = guard.as_ref() {
            return Ok(ca.clone());
        }
        fs::create_dir_all(&self.cert_dir).map_err(cert_error)?;
        let cert_path = self.cert_dir.join("ca.crt");
        let key_path = self.cert_dir.join("ca.key");

        let ca = if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path).map_err(cert_error)?;
            let key_pem = fs::read_to_string(&key_path).map_err(cert_error)?;
            let key = KeyPair::from_pem(&key_pem).map_err(cert_error)?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem).map_err(cert_error)?;
            CaMaterial {
                cert: params.self_signed(&key).map_err(cert_error)?,
                key,
                original_pem: cert_pem,
            }
        } else {
            let generated = generate_ca()?;
            fs::write(&cert_path, generated.cert.pem()).map_err(cert_error)?;
            fs::write(&key_path, generated.key.serialize_pem()).map_err(cert_error)?;
            generated
        };

        let ca = Arc::new(ca);
        *guard = Some(ca.clone());
        Ok(ca)
    }
}

impl CertProvider for RcgenCertProvider {
    fn host_cert(&self, hostname: &str) -> Result<HostCert, ProxyError> {
        let ca = self.ca()?;
        let cert_path = self.cert_dir.join(format!("{hostname}.crt"));
        let key_path = self.cert_dir.join(format!("{hostname}.key"));

        if cert_path.exists() && key_path.exists() {
            return HostCert::from_pem_files(&cert_path, &key_path);
        }

        let leaf_key = KeyPair::generate().map_err(cert_error)?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, hostname.to_owned());
        params.subject_alt_names = host_san(hostname)?;
        let cert = params
            .signed_by(&leaf_key, &ca.cert, &ca.key)
            .map_err(cert_error)?;

        fs::write(&cert_path, cert.pem()).map_err(cert_error)?;
        fs::write(&key_path, leaf_key.serialize_pem()).map_err(cert_error)?;

        HostCert::from_generated(&cert, &leaf_key)
    }

    fn ca_cert_pem(&self) -> Result<String, ProxyError> {
        Ok(self.ca()?.original_pem.clone())
    }
}

fn generate_ca() -> Result<CaMaterial, ProxyError> {
    let key = KeyPair::generate().map_err(cert_error)?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "API-AutoTester CA".to_owned());
    params
        .distinguished_name
        .push(DnType::CommonName, "API-AutoTester Root CA".to_owned());
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let cert = params.self_signed(&key).map_err(cert_error)?;
    let original_pem = cert.pem();
    Ok(CaMaterial {
        cert,
        key,
        original_pem,
    })
}

fn host_san(hostname: &str) -> Result<Vec<SanType>, ProxyError> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        Ok(vec![SanType::IpAddress(ip)])
    } else {
        let name = rcgen::Ia5String::try_from(hostname).map_err(cert_error)?;
        Ok(vec![SanType::DnsName(name)])
    }
}

fn cert_error<E: std::fmt::Display>(error: E) -> ProxyError {
    ProxyError::Cert(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{CertProvider, RcgenCertProvider};

    #[test]
    fn generates_and_caches_ca() {
        let directory = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(directory.path().to_path_buf());

        let pem = provider.ca_cert_pem().unwrap();

        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(directory.path().join("ca.crt").exists());
        assert!(directory.path().join("ca.key").exists());
    }

    #[test]
    fn ca_is_reused_across_instances() {
        let directory = tempfile::tempdir().unwrap();
        let first = RcgenCertProvider::new(directory.path().to_path_buf());
        let pem1 = first.ca_cert_pem().unwrap();

        let second = RcgenCertProvider::new(directory.path().to_path_buf());
        let pem2 = second.ca_cert_pem().unwrap();

        assert_eq!(pem1, pem2);
    }

    #[test]
    fn generates_and_caches_host_cert() {
        let directory = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(directory.path().to_path_buf());

        let host = provider.host_cert("example.com").unwrap();

        assert!(host.server_config().is_ok());
        assert!(directory.path().join("example.com.crt").exists());
        assert!(directory.path().join("example.com.key").exists());
    }

    #[test]
    fn host_cert_is_cached() {
        let directory = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(directory.path().to_path_buf());

        let first = provider.host_cert("example.com").unwrap();
        let second = provider.host_cert("example.com").unwrap();

        assert!(first.server_config().is_ok());
        assert!(second.server_config().is_ok());
    }

    #[test]
    fn generates_cert_for_ip_host() {
        let directory = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(directory.path().to_path_buf());

        let host = provider.host_cert("127.0.0.1").unwrap();

        assert!(host.server_config().is_ok());
    }
}
