use super::{RatsClientVerifier, VerifyCallback};
use crate::cert::create::CertBuilder;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::Result;
use crate::tee::{claims::Claims, AutoAttester};
use crate::transport::{
    GenericSecureTransPort, GenericSecureTransPortRead, GenericSecureTransPortWrite,
};
use maybe_async::maybe_async;
use std::sync::Arc;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// Re-export the TlsStream type for HTTP integration
pub use tokio_rustls::server::TlsStream as ServerTlsStream;

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

/// A rustls-based TLS server with TEE remote attestation support.
///
/// This server performs RA-TLS negotiation and can be used either:
/// 1. With the `send()`/`receive()` methods for simple byte-level communication
/// 2. By taking the underlying `TlsStream` via `into_stream()` for HTTP/gRPC integration
///
/// # Example: HTTP Integration with Axum
///
/// ```ignore
/// use rats_rs::transport::rustls::RustlsServerBuilder;
/// use axum::{Router, routing::get};
/// use hyper_util::rt::TokioIo;
///
/// let listener = TcpListener::bind("0.0.0.0:8080").await?;
///
/// loop {
///     let (stream, addr) = listener.accept().await?;
///     
///     let mut server = RustlsServerBuilder::new(stream)
///         .with_custom_claims(claims)
///         .build()
///         .await?;
///     
///     // Perform RA-TLS negotiation (attestation happens here)
///     server.negotiate().await?;
///     
///     // Take the stream for HTTP use
///     let tls_stream = server.into_stream()?;
///     let io = TokioIo::new(tls_stream);
///     
///     // Now use with hyper/axum...
/// }
/// ```
pub struct RustlsServer {
    acceptor: TlsAcceptor,
    stream: Option<TcpStream>,
    state: Option<NegotiatedState>,
}

impl RustlsServer {
    /// Creates a new RustlsServer.
    ///
    /// # Arguments
    /// * `stream` - The TCP stream from an accepted connection
    /// * `mutual` - Whether to verify client certificates (mutual attestation)
    ///
    /// # Deprecated
    /// Consider using `RustlsServerBuilder` for more flexibility.
    #[maybe_async]
    pub async fn new(stream: TcpStream, mutual: bool) -> Result<Self> {
        RustlsServerBuilder::new(stream)
            .with_verify_peer(mutual)
            .build()
            .await
    }

    /// Consumes the server and returns the underlying TLS stream.
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
    /// let mut server = RustlsServerBuilder::new(stream)
    ///     .build()
    ///     .await?;
    ///
    /// server.negotiate().await?;
    ///
    /// // Take the stream for HTTP use with axum
    /// let tls_stream = server.into_stream()?;
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
    /// Use this when you need the stream but want to keep the server around.
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

/// Builder for creating `RustlsServer` instances with custom configuration.
///
/// # Example
/// ```ignore
/// use rats_rs::transport::rustls::RustlsServerBuilder;
/// use rats_rs::tee::claims::Claims;
///
/// let mut claims = Claims::new();
/// claims.insert("appId".to_string(), b"secret-broker".to_vec());
///
/// let server = RustlsServerBuilder::new(tcp_stream)
///     .with_verify_peer(true)
///     .with_custom_claims(claims)
///     .build()
///     .await?;
/// ```
pub struct RustlsServerBuilder {
    stream: TcpStream,
    verify_peer: bool,
    custom_claims: Option<Claims>,
    verify_callback: Option<VerifyCallback>,
}

impl RustlsServerBuilder {
    /// Creates a new builder for the specified TCP stream.
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            verify_peer: false,
            custom_claims: None,
            verify_callback: None,
        }
    }

    /// Sets whether the server should verify client certificates (mutual attestation).
    pub fn with_verify_peer(mut self, verify_peer: bool) -> Self {
        self.verify_peer = verify_peer;
        self
    }

    /// Sets custom claims to be included in the attestation certificate.
    ///
    /// These claims will be cryptographically bound to the TEE attestation
    /// evidence and can be verified by the client.
    pub fn with_custom_claims(mut self, claims: Claims) -> Self {
        self.custom_claims = Some(claims);
        self
    }

    /// Sets a custom verification callback that is called after RA-TLS verification.
    ///
    /// The callback receives the extracted claims from the client's certificate
    /// and can perform additional validation (e.g., check specific RTMR values,
    /// verify appId, etc.).
    ///
    /// Only used when `verify_peer` is true (mutual attestation).
    pub fn with_verify_callback(mut self, callback: VerifyCallback) -> Self {
        self.verify_callback = Some(callback);
        self
    }

    /// Builds the `RustlsServer`.
    #[maybe_async]
    pub async fn build(self) -> Result<RustlsServer> {
        let privkey = DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::P256)?;

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
        let config_builder = rustls::ServerConfig::builder();

        let config = if self.verify_peer {
            config_builder
                .with_client_cert_verifier(Arc::new(RatsClientVerifier {
                    default_client_verifier: WebPkiClientVerifier::builder(Arc::new({
                        // XXX: only to bypass empty test of WebPkiClientVerifier
                        let mut root = rustls::RootCertStore::empty();
                        let privkey =
                            DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::P256)?;
                        let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
                            .build_with_private_key(&privkey)
                            .await?
                            .cert_to_der()?;
                        root.add(cert.into())?;
                        root
                    }))
                    .build()?,
                    callback: self.verify_callback,
                }))
                .with_single_cert(vec![cert.into()], tmp.into())?
        } else {
            config_builder
                .with_no_client_auth()
                .with_single_cert(vec![cert.into()], tmp.into())?
        };

        Ok(RustlsServer {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            stream: Some(self.stream),
            state: None,
        })
    }
}

#[maybe_async]
impl GenericSecureTransPort for RustlsServer {
    async fn negotiate(&mut self) -> Result<()> {
        let acceptor = self.acceptor.clone();
        let stream = std::mem::replace(&mut self.stream, None).unwrap();
        let tls_stream = acceptor.accept(stream).await?;

        // Store as full stream - will be split on first read/write if needed
        self.state = Some(NegotiatedState::Full(tls_stream));
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for RustlsServer {
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
impl GenericSecureTransPortRead for RustlsServer {
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
