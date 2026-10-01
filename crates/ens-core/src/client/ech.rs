use std::{num::TryFromIntError, sync::Arc, time::Duration};

use http::Uri;
use log::{info, warn};
use rustls::{
    client::EchConfig,
    crypto::{aws_lc_rs::hpke::ALL_SUPPORTED_SUITES, hpke::Hpke},
    pki_types::EchConfigListBytes,
};
use telio_sockets::SocketPool;

use super::{connect_error, connect_tcp, make_tls_connector, EchMode, Error, TlsOptions};

pub(super) async fn bootstrap(
    uri: &Uri,
    tls: &TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_pq: bool,
    root_certificate: &[u8],
    timeout: Duration,
) -> Result<EchConfig, Error> {
    let retry_configs =
        retry_configs(uri, tls, pool, allow_only_pq, root_certificate, timeout).await?;

    let ech_config = EchConfig::new(
        EchConfigListBytes::from(retry_configs),
        ALL_SUPPORTED_SUITES,
    )
    .map_err(|e| {
        warn!("ECH bootstrapping failed, invalid retry configs: {e:?}");
        Error::EchBootstrappingRejected
    })?;

    info!("ECH bootstrapping success");
    Ok(ech_config)
}

pub(super) async fn retry_configs(
    uri: &Uri,
    tls: &TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_pq: bool,
    root_certificate: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let handshake = handshake(uri, tls, pool, allow_only_pq, root_certificate);

    tokio::time::timeout(timeout, handshake)
        .await
        .map_err(|e| Error::EchBootstrappingFailed { source: e.into() })?
}

async fn handshake(
    uri: &Uri,
    tls: &TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_pq: bool,
    root_certificate: &[u8],
) -> Result<Vec<u8>, Error> {
    let (host, expected_tls_hostname, tcp_stream) =
        connect_tcp(uri, &pool, tls).await.map_err(connect_error)?;

    let domain =
        tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| {
            Error::Internal {
                reason: format!("malformed server name: {e}"),
            }
        })?;

    let tls_connector = make_tls_connector(
        allow_only_pq,
        root_certificate,
        EchMode::BootstrapWithExpectedServerName(expected_tls_hostname),
    )
    .map_err(|source| Error::EchBootstrappingFailed { source })?;

    // Getting an error here is desired - this is the way tls/rustls transmit
    // the retry configs with up-to-date crypto keys that will be used in the
    // second connection to establish TLS with ECH
    let Err(e) = tls_connector.connect(domain, tcp_stream).await else {
        return Err(Error::EchBootstrappingRejected);
    };

    match e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        // This is a successful ECH bootstrap.
        Some(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(Some(retry_configs)),
        )) => {
            use rustls::internal::msgs::codec::Codec;
            Ok(retry_configs.get_encoding())
        }
        // App asked for ECH bootstrapping but the server is not returning
        // fresh retry configs, so it's not possible to complete the bootstrap.
        Some(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(None),
        )) => Err(Error::EchBootstrappingRejected),
        // Server presented an invalid certificate, which is not a transient
        // connection failure, so we will not automatically retry.
        Some(rustls::Error::InvalidCertificate(_)) => Err(Error::UntrustedCertificate {
            vpn_uri: uri.to_string(),
            reason: e.to_string(),
        }),
        // Things like captive portals can inject invalid (from the
        // point of view of TLS) bytes, but are not necessarily
        // persistent errors - user can log into the captive portal
        // and gain access to the internet, etc...
        _ => Err(Error::EchBootstrappingFailed { source: e }),
    }
}
#[derive(Debug, thiserror::Error)]
pub enum KeyConfigError {
    #[error("Integer conversion failed: {0}")]
    IntConversion(#[from] TryFromIntError),
    #[error("Key generation failed: {0}")]
    KeyGeneration(#[from] rustls::Error),
}

fn random_key_config(public_domain: &str) -> Result<Vec<u8>, KeyConfigError> {
    // take the first entry of supported suites
    let hpke = rustls::crypto::aws_lc_rs::hpke::DH_KEM_P256_HKDF_SHA256_AES_128;

    let mut buf = Vec::new();

    // push number of entries to be filled later
    buf.extend(0u16.to_be_bytes());

    // `ECHConfig[0]`
    buf.extend(0xfe0du16.to_be_bytes()); // version
    buf.extend(0u16.to_be_bytes()); // length to be filled later

    let offset = buf.len();

    // `HpkeKeyConfig`
    buf.extend([0u8]); // config_id
    buf.extend(u16::from(hpke.suite().kem).to_be_bytes()); // kem_id

    let (pubkey, _) = hpke.generate_key_pair()?;
    let key = pubkey.0;

    buf.extend(u16::try_from(key.len())?.to_be_bytes()); // public key
    buf.extend(key);

    // `HpkeSymetricCipherSuite`
    buf.extend(4u16.to_be_bytes()); // len + 4

    buf.extend(u16::from(hpke.suite().sym.kdf_id).to_be_bytes()); // kdf_id
    buf.extend(u16::from(hpke.suite().sym.aead_id).to_be_bytes()); // aead_id

    buf.extend([0u8]); // maximum_name_length

    let opaque_name = public_domain.as_bytes();
    let len: u8 = opaque_name.len().min(255).try_into()?;

    buf.extend([len]);
    buf.extend(&opaque_name[..len as usize]); // public_name

    buf.extend(0u16.to_be_bytes()); // extensions

    // fixup `ECHConfig` length

    let len = u16::try_from(buf.len() - offset)?;
    buf[(offset - 2)..][..2].copy_from_slice(&len.to_be_bytes());

    // fixup whole list length
    let len = u16::try_from(buf.len() - 2)?;
    buf[..2].copy_from_slice(&len.to_be_bytes());

    Ok(buf)
}

pub(super) fn generate_random_ech_config_list(
) -> Result<EchConfigListBytes<'static>, KeyConfigError> {
    let domain = generate_random_domain();
    let ech_config_list = random_key_config(&domain)?;
    Ok(EchConfigListBytes::from(ech_config_list))
}

fn generate_random_domain() -> String {
    // Most popular English words according to https://en.wikipedia.org/wiki/Most_common_words_in_English
    const NOUNS: &[&str] = &[
        "time",
        "person",
        "year",
        "way",
        "day",
        "thing",
        "man",
        "world",
        "life",
        "hand",
        "part",
        "child",
        "eye",
        "woman",
        "place",
        "work",
        "week",
        "case",
        "point",
        "government",
        "company",
        "number",
        "group",
        "problem",
        "fact",
    ];

    const VERBS: &[&str] = &[
        "be", "have", "do", "say", "get", "make", "go", "know", "take", "see", "come", "think",
        "look", "want", "give", "use", "find", "tell", "ask", "work", "seem", "feel", "try",
        "leave", "call",
    ];

    const ADJECTIVES: &[&str] = &[
        "good",
        "new",
        "first",
        "last",
        "long",
        "great",
        "little",
        "own",
        "other",
        "old",
        "right",
        "big",
        "high",
        "different",
        "small",
        "large",
        "next",
        "early",
        "young",
        "important",
        "few",
        "public",
        "bad",
        "same",
        "able",
    ];

    const CODES: &[&str] = &["io", "org", "com"];

    const SEPARATORS: &[&str] = &["", "-"];

    fn sample<'a>(slice: &[&'a str]) -> &'a str {
        slice[rand::random_range(0..slice.len())]
    }

    let mut domain = String::new();

    let sep = sample(SEPARATORS);

    domain.push_str(sample(VERBS));
    domain.push_str(sep);

    if rand::random_bool(0.5) {
        domain.push_str(sample(ADJECTIVES));
        domain.push_str(sep);
    }

    domain.push_str(sample(NOUNS));
    domain.push('.');
    domain.push_str(sample(CODES));

    domain
}
