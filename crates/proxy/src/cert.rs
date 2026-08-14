use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams, DnType,
    IsCa, KeyIdMethod, KeyPair, SanType, SerialNumber,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::OffsetDateTime;

use crate::error::ProxyError;

/// Upper bound on in-memory host certificates so a long-running capture with
/// many distinct hostnames cannot grow the cache without limit.
const MAX_CACHED_HOST_CERTS: usize = 4096;

/// Validity of generated per-host certificates (matches the Python reference).
const HOST_CERT_VALIDITY_DAYS: i64 = 365;

/// Where the proxy serves its CRL so strict clients (Windows schannel) can
/// satisfy revocation checks against MITM certificates.
const CRL_URL: &str = "http://127.0.0.1:8080/ca.crl";

/// A generated certificate bundle for one host, ready to build a rustls
/// server configuration for MITM TLS interception. Host certificates are
/// shared through `Arc` so the cached instance can be reused by every
/// connection to the same host without copying key material.
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
    fn host_cert(&self, hostname: &str) -> Result<Arc<HostCert>, ProxyError>;
    fn ca_cert_pem(&self) -> Result<String, ProxyError>;
    /// DER bytes of an (empty) CRL signed by the CA, served by the proxy so
    /// strict clients can pass revocation checks on MITM certificates.
    fn ca_crl_der(&self) -> Result<Vec<u8>, ProxyError>;
}

struct CaMaterial {
    cert: Certificate,
    key: KeyPair,
    original_pem: String,
}

/// Certificate authority + per-host certificate generation, cached on disk
/// and in memory. Mirrors the Python `CertManager`: CA reused across
/// restarts, host certs generated once per host and cached.
pub struct RcgenCertProvider {
    cert_dir: PathBuf,
    ca: Mutex<Option<Arc<CaMaterial>>>,
    host_certs: Mutex<HashMap<String, Arc<HostCert>>>,
}

impl RcgenCertProvider {
    pub fn new(cert_dir: PathBuf) -> Self {
        Self {
            cert_dir,
            ca: Mutex::new(None),
            host_certs: Mutex::new(HashMap::new()),
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

        let ca = match load_existing_ca(&cert_path, &key_path) {
            Ok(ca) => ca,
            // Missing, expired, or unreadable → regenerate (Python parity).
            Err(_) => {
                let generated = generate_ca()?;
                fs::write(&cert_path, generated.cert.pem()).map_err(cert_error)?;
                fs::write(&key_path, generated.key.serialize_pem()).map_err(cert_error)?;
                generated
            }
        };

        let ca = Arc::new(ca);
        *guard = Some(ca.clone());
        Ok(ca)
    }
}

impl CertProvider for RcgenCertProvider {
    fn host_cert(&self, hostname: &str) -> Result<Arc<HostCert>, ProxyError> {
        self.host_cert_cached(hostname)
    }

    fn ca_cert_pem(&self) -> Result<String, ProxyError> {
        Ok(self.ca()?.original_pem.clone())
    }

    fn ca_crl_der(&self) -> Result<Vec<u8>, ProxyError> {
        let ca = self.ca()?;
        let params = CertificateRevocationListParams {
            this_update: OffsetDateTime::now_utc() - time::Duration::days(1),
            next_update: OffsetDateTime::now_utc() + time::Duration::days(30),
            crl_number: SerialNumber::from_slice(&[1]),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(&ca.cert, &ca.key).map_err(cert_error)?;
        Ok(crl.der().to_vec())
    }
}

impl RcgenCertProvider {
    fn host_cert_cached(&self, hostname: &str) -> Result<Arc<HostCert>, ProxyError> {
        let mut cache = self
            .host_certs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(cert) = cache.get(hostname) {
            return Ok(cert.clone());
        }

        let cert = Arc::new(self.load_or_generate_host_cert(hostname)?);
        if cache.len() >= MAX_CACHED_HOST_CERTS {
            cache.clear();
        }
        cache.insert(hostname.to_owned(), cert.clone());
        Ok(cert)
    }

    /// Reads the on-disk certificate or generates a fresh one. The lock in
    /// `host_cert_cached` is held across this call so concurrent first
    /// connections to the same host cannot generate competing certificates.
    fn load_or_generate_host_cert(&self, hostname: &str) -> Result<HostCert, ProxyError> {
        let ca = self.ca()?;
        let cert_path = self.cert_dir.join(format!("{hostname}.crt"));
        let key_path = self.cert_dir.join(format!("{hostname}.key"));

        if cert_path.exists() && key_path.exists() && host_cert_has_crl_dp(&cert_path) {
            return HostCert::from_pem_files(&cert_path, &key_path);
        }

        let leaf_key = KeyPair::generate().map_err(cert_error)?;
        let mut params = CertificateParams::default();
        params.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(1);
        params.not_after =
            OffsetDateTime::now_utc() + time::Duration::days(HOST_CERT_VALIDITY_DAYS);
        params
            .distinguished_name
            .push(DnType::CommonName, hostname.to_owned());
        params.subject_alt_names = host_san(hostname)?;
        params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
            uris: vec![CRL_URL.to_owned()],
        }];
        let cert = params
            .signed_by(&leaf_key, &ca.cert, &ca.key)
            .map_err(cert_error)?;

        fs::write(&cert_path, cert.pem()).map_err(cert_error)?;
        fs::write(&key_path, leaf_key.serialize_pem()).map_err(cert_error)?;

        HostCert::from_generated(&cert, &leaf_key)
    }

    #[cfg(test)]
    fn cached_host_count(&self) -> usize {
        self.host_certs.lock().map(|cache| cache.len()).unwrap_or(0)
    }
}

/// Loads a CA from disk, rejecting expired or unreadable certificates so the
/// caller regenerates them (mirrors the Python `_is_ca_valid` check).
fn load_existing_ca(cert_path: &Path, key_path: &Path) -> Result<CaMaterial, ProxyError> {
    let cert_pem = fs::read_to_string(cert_path).map_err(cert_error)?;
    let key_pem = fs::read_to_string(key_path).map_err(cert_error)?;
    let params = CertificateParams::from_ca_cert_pem(&cert_pem).map_err(cert_error)?;
    if params.not_after < OffsetDateTime::now_utc() {
        return Err(ProxyError::Cert("CA certificate has expired".to_owned()));
    }
    let key = load_key_pair(&key_pem)?;
    Ok(CaMaterial {
        cert: params.self_signed(&key).map_err(cert_error)?,
        key,
        original_pem: cert_pem,
    })
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
    // Mirror the Python reference: always include the DNS name and, when the
    // hostname is an IP literal, also the IP SAN so both client paths verify.
    let mut sans = Vec::new();
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        sans.push(SanType::IpAddress(ip));
    }
    let name = rcgen::Ia5String::try_from(hostname).map_err(cert_error)?;
    sans.push(SanType::DnsName(name));
    Ok(sans)
}

fn cert_error<E: std::fmt::Display>(error: E) -> ProxyError {
    ProxyError::Cert(error.to_string())
}

/// Whether an on-disk host certificate carries the CRL distribution points
/// extension. Older generated certs lack it, so strict clients cannot check
/// revocation; such certs are regenerated with the extension present.
fn host_cert_has_crl_dp(path: &Path) -> bool {
    let Ok(pem) = std::fs::read(path) else {
        return false;
    };
    let Ok(der) = CertificateDer::from_pem_slice(&pem) else {
        return false;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der.as_ref()) else {
        return false;
    };
    cert.extensions()
        .iter()
        .any(|extension| extension.oid.to_string() == "2.5.29.31")
}

/// Parses a CA private key. rcgen expects PKCS#8, but the Python reference
/// writes PKCS#1 ("RSA PRIVATE KEY"); convert when possible so the existing
/// (already trusted) CA keeps its identity across the migration.
fn load_key_pair(key_pem: &str) -> Result<KeyPair, ProxyError> {
    if let Ok(key) = KeyPair::from_pem(key_pem) {
        return Ok(key);
    }
    if let Ok(rsa_key) = RsaPrivateKey::from_pkcs1_pem(key_pem) {
        if let Ok(pkcs8) = rsa_key.to_pkcs8_der() {
            let der = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
            if let Ok(key) = KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_RSA_SHA256) {
                return Ok(key);
            }
        }
    }
    Err(ProxyError::Cert(
        "could not parse CA key pair (expected PKCS#8 or PKCS#1 PEM)".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{CertProvider, RcgenCertProvider};
    use rustls::pki_types::pem::PemObject;

    #[test]
    fn ca_regenerates_when_expired() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let dir = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "API-AutoTester Root CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(400);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let expired = params.self_signed(&key).unwrap();
        std::fs::write(dir.path().join("ca.crt"), expired.pem()).unwrap();
        std::fs::write(dir.path().join("ca.key"), key.serialize_pem()).unwrap();
        let expired_pem = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();

        let provider = RcgenCertProvider::new(dir.path().to_path_buf());
        let _ = provider.ca_cert_pem().unwrap();

        let regenerated = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
        assert_ne!(
            expired_pem.trim(),
            regenerated.trim(),
            "expired CA must be regenerated"
        );
    }

    #[test]
    fn host_cert_validity_is_365_days() {
        let dir = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(dir.path().to_path_buf());
        let _ = provider.host_cert("example.com").unwrap();

        let pem = std::fs::read(dir.path().join("example.com.crt")).unwrap();
        let der = rustls::pki_types::CertificateDer::from_pem_slice(&pem).unwrap();
        let (_, x509) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        let validity = x509.validity();
        let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / 86_400;
        assert!(
            (364..=366).contains(&days),
            "expected ~365 days, got {days}"
        );
    }

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
    fn host_cert_is_cached_in_memory() {
        let directory = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(directory.path().to_path_buf());

        let _ = provider.host_cert("example.com").unwrap();
        assert_eq!(provider.cached_host_count(), 1);

        let _ = provider.host_cert("example.com").unwrap();
        assert_eq!(
            provider.cached_host_count(),
            1,
            "second call reuses the cache"
        );
    }

    #[test]
    fn generates_cert_for_ip_host() {
        let directory = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(directory.path().to_path_buf());

        let host = provider.host_cert("127.0.0.1").unwrap();

        assert!(host.server_config().is_ok());
    }

    #[test]
    fn parses_pkcs1_ca_key() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs1::EncodeRsaPrivateKey;

        let mut rng = rand::thread_rng();
        let rsa_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkcs1_pem = rsa_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap()
            .to_string();
        assert!(pkcs1_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));

        let key = super::load_key_pair(&pkcs1_pem).unwrap();
        assert!(key.serialize_pem().contains("PRIVATE KEY"));
    }
}
