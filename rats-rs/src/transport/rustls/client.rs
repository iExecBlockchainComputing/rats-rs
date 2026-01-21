use super::RatsServerVerifier;
use crate::cert::create::CertBuilder;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::Result;
use crate::tee::{claims::Claims, AutoAttester};
use crate::transport::{
    GenericSecureTransPort, GenericSecureTransPortRead, GenericSecureTransPortWrite,
};
use maybe_async::maybe_async;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{IpAddr as RustlsIpAddr, PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::rustls::{self, pki_types, ClientConfig};
use tokio_rustls::TlsConnector;

/// Re-export the TlsStream type for HTTP integration
pub use tokio_rustls::client::TlsStream as ClientTlsStream;

/// Internal state after negotiation - either split for read/write ops or full stream for HTTP
enum NegotiatedState {
    /// Split into reader/writer for GenericSecureTransPort operations
    Split {
        reader: ReadHalf<TlsStream<TcpStream>>,
        writer: WriteHalf<TlsStream<TcpStream>>,
    },
    /// Full stream available (before into_stream() is called)
    Full(TlsStream<TcpStream>),
    /// Stream has been taken via into_stream()
    Taken,
}

/// A rustls-based TLS client with TEE remote attestation support.
///
/// This client performs RA-TLS negotiation and can be used either:
/// 1. With the `send()`/`receive()` methods for simple byte-level communication
/// 2. By taking the underlying `TlsStream` via `into_stream()` for HTTP/gRPC integration
///
/// # Example: HTTP Integration with Hyper
///
/// ```ignore
/// use rats_rs::transport::rustls::RustlsClientBuilder;
/// use hyper_util::rt::TokioIo;
///
/// let mut client = RustlsClientBuilder::new("127.0.0.1:8080")
///     .with_attest_self(true)
///     .with_custom_claims(claims)
///     .build()
///     .await?;
///
/// // Perform RA-TLS negotiation (attestation happens here)
/// client.negotiate().await?;
///
/// // Take the stream for HTTP use
/// let tls_stream = client.into_stream()?;
/// let io = TokioIo::new(tls_stream);
///
/// // Now use with hyper...
/// ```
#[allow(unused)]
pub struct RustlsClient {
    connector: TlsConnector,
    addr: String,
    state: Option<NegotiatedState>,
}

impl RustlsClient {
    /// Creates a new RustlsClient.
    ///
    /// # Arguments
    /// * `addr` - The server address in "host:port" format
    /// * `mutual` - Whether to perform mutual attestation (client attests to server)
    ///
    /// # Deprecated
    /// Consider using `RustlsClientBuilder` for more flexibility.
    #[maybe_async]
    pub async fn new(addr: &str, mutual: bool) -> Result<Self> {
        RustlsClientBuilder::new(addr)
            .with_attest_self(mutual)
            .build()
            .await
    }

    /// Consumes the client and returns the underlying TLS stream.
    ///
    /// This method is useful for HTTP/gRPC integration where you need
    /// direct access to the stream. The stream can be used with:
    /// - `hyper` for HTTP/1.1 and HTTP/2
    /// - `tonic` for gRPC
    /// - `axum` via hyper
    /// - Any other library that accepts `AsyncRead + AsyncWrite`
    ///
    /// # Returns
    /// The underlying `TlsStream<TcpStream>` if available.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `negotiate()` hasn't been called yet
    /// - The stream has already been taken
    /// - The stream was split for read/write operations
    ///
    /// # Example
    /// ```ignore
    /// let mut client = RustlsClientBuilder::new("127.0.0.1:8080")
    ///     .with_attest_self(true)
    ///     .build()
    ///     .await?;
    ///
    /// client.negotiate().await?;
    ///
    /// // Take the stream for HTTP use
    /// let stream = client.into_stream()?;
    /// ```
    pub fn into_stream(mut self) -> Result<TlsStream<TcpStream>> {
        match self.state.take() {
            Some(NegotiatedState::Full(stream)) => Ok(stream),
            Some(NegotiatedState::Split { .. }) => Err(crate::errors::Error::kind(
                crate::errors::ErrorKind::TransportStreamAlreadySplit,
            )),
            Some(NegotiatedState::Taken) | None => Err(crate::errors::Error::kind(
                crate::errors::ErrorKind::TransportStreamNotAvailable,
            )),
        }
    }

    /// Takes the TLS stream without consuming self.
    ///
    /// After calling this, `send()`/`receive()` will no longer work.
    /// Use this when you need the stream but want to keep the client around.
    pub fn take_stream(&mut self) -> Result<TlsStream<TcpStream>> {
        match self.state.take() {
            Some(NegotiatedState::Full(stream)) => {
                self.state = Some(NegotiatedState::Taken);
                Ok(stream)
            }
            Some(NegotiatedState::Split { .. }) => Err(crate::errors::Error::kind(
                crate::errors::ErrorKind::TransportStreamAlreadySplit,
            )),
            Some(NegotiatedState::Taken) | None => Err(crate::errors::Error::kind(
                crate::errors::ErrorKind::TransportStreamNotAvailable,
            )),
        }
    }

    /// Ensures the stream is split for read/write operations.
    fn ensure_split(&mut self) -> Result<()> {
        if let Some(NegotiatedState::Full(stream)) = self.state.take() {
            let (reader, writer) = split(stream);
            self.state = Some(NegotiatedState::Split { reader, writer });
        }
        Ok(())
    }
}

/// Builder for creating `RustlsClient` instances with custom configuration.
///
/// # Example
/// ```ignore
/// use rats_rs::transport::rustls::RustlsClientBuilder;
/// use rats_rs::tee::claims::Claims;
///
/// let mut claims = Claims::new();
/// claims.insert("appId".to_string(), b"my-app".to_vec());
///
/// let client = RustlsClientBuilder::new("127.0.0.1:8080")
///     .with_attest_self(true)
///     .with_custom_claims(claims)
///     .build()
///     .await?;
/// ```
pub struct RustlsClientBuilder {
    addr: String,
    attest_self: bool,
    custom_claims: Option<Claims>,
}

impl RustlsClientBuilder {
    /// Creates a new builder for the specified address.
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            attest_self: false,
            custom_claims: None,
        }
    }

    /// Sets whether the client should attest itself to the server (mutual attestation).
    pub fn with_attest_self(mut self, attest_self: bool) -> Self {
        self.attest_self = attest_self;
        self
    }

    /// Sets custom claims to be included in the attestation certificate.
    ///
    /// These claims will be cryptographically bound to the TEE attestation
    /// evidence and can be verified by the server.
    pub fn with_custom_claims(mut self, claims: Claims) -> Self {
        self.custom_claims = Some(claims);
        self
    }

    /// Builds the `RustlsClient`.
    #[maybe_async]
    pub async fn build(self) -> Result<RustlsClient> {
        let config_builder = rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(rustls::RootCertStore::empty()));

        let config = if self.attest_self {
            let privkey = DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::Rsa2048)?;

            let cert_builder = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256);
            let cert_builder = if let Some(claims) = self.custom_claims {
                cert_builder.with_claims(claims)
            } else {
                cert_builder.with_claims(Claims::new())
            };

            let cert = cert_builder
                .build_with_private_key(&privkey)
                .await?
                .cert_to_der()?;

            let tmp: PrivatePkcs8KeyDer = privkey.to_pkcs8_der()?.as_bytes().to_vec().into();
            config_builder.with_client_auth_cert(vec![cert.into()], tmp.into())?
        } else {
            config_builder.with_no_client_auth()
        };

        // Set up RA-TLS certificate verifier
        let mut config = config;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(RatsServerVerifier {
                default_server_verifier: WebPkiServerVerifier::builder(Arc::new({
                    // XXX: only to bypass empty test of WebPkiServerVerifier
                    let mut root = rustls::RootCertStore::empty();
                    let privkey =
                        DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::Rsa2048)?;
                    let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
                        .build_with_private_key(&privkey)
                        .await?
                        .cert_to_der()?;
                    root.add(cert.into())?;
                    root
                }))
                .build()?,
            }));

        Ok(RustlsClient {
            connector: TlsConnector::from(Arc::new(config)),
            addr: self.addr,
            state: None,
        })
    }
}

#[maybe_async]
impl GenericSecureTransPort for RustlsClient {
    async fn negotiate(&mut self) -> Result<()> {
        let socket_addr: SocketAddr = self.addr.parse()?;
        let stream = TcpStream::connect(&self.addr).await?;

        // Convert std IpAddr to rustls ServerName
        let ip_addr = socket_addr.ip();
        let domain = ServerName::IpAddress(RustlsIpAddr::from(ip_addr));

        let tls_stream = self.connector.connect(domain, stream).await?;

        // Store as full stream - will be split on first read/write if needed
        self.state = Some(NegotiatedState::Full(tls_stream));
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for RustlsClient {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.ensure_split()?;
        if let Some(NegotiatedState::Split { writer, .. }) = &mut self.state {
            writer.write_all(bytes).await?;
            Ok(())
        } else {
            Err(crate::errors::Error::kind(
                crate::errors::ErrorKind::TransportStreamNotAvailable,
            ))
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.ensure_split()?;
        if let Some(NegotiatedState::Split { writer, .. }) = &mut self.state {
            writer.shutdown().await?;
            Ok(())
        } else {
            Err(crate::errors::Error::kind(
                crate::errors::ErrorKind::TransportStreamNotAvailable,
            ))
        }
    }
}

#[maybe_async]
impl GenericSecureTransPortRead for RustlsClient {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.ensure_split()?;
        if let Some(NegotiatedState::Split { reader, .. }) = &mut self.state {
            let len = reader.read(buf).await?;
            Ok(len)
        } else {
            Err(crate::errors::Error::kind(
                crate::errors::ErrorKind::TransportStreamNotAvailable,
            ))
        }
    }
}
