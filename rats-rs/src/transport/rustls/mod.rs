//! Rustls-based transport layer with TEE remote attestation support.
//!
//! This module provides TLS client and server implementations using `tokio-rustls`
//! with integrated TEE remote attestation. The attestation evidence is embedded
//! in the TLS certificates and verified during the handshake.
//!
//! # Features
//!
//! - **RA-TLS**: Remote Attestation TLS with TEE evidence in certificates
//! - **Mutual Attestation**: Both client and server can attest to each other
//! - **Custom Claims**: Application-specific claims bound to attestation
//! - **HTTP Integration**: Direct access to `TlsStream` for use with HTTP libraries
//!
//! # HTTP/gRPC Integration
//!
//! After negotiation, you can take the underlying `TlsStream` for use with
//! HTTP libraries like `hyper`, `axum`, or gRPC libraries like `tonic`.
//!
//! ## Client Example with Hyper
//!
//! ```ignore
//! use rats_rs::transport::rustls::{RustlsClientBuilder, ClientTlsStream};
//! use rats_rs::transport::GenericSecureTransPort;
//! use hyper_util::rt::TokioIo;
//! use hyper::client::conn::http1;
//!
//! // Create and configure the RA-TLS client
//! let mut client = RustlsClientBuilder::new("127.0.0.1:8080")
//!     .with_attest_self(true)
//!     .with_custom_claims(claims)
//!     .build()
//!     .await?;
//!
//! // Perform RA-TLS negotiation (TEE attestation happens here!)
//! client.negotiate().await?;
//!
//! // Take the stream for HTTP use
//! let tls_stream = client.into_stream()?;
//! let io = TokioIo::new(tls_stream);
//!
//! // Use with hyper
//! let (mut sender, conn) = http1::handshake(io).await?;
//! tokio::spawn(async move { conn.await });
//!
//! let req = Request::get("/secret").body(Empty::<Bytes>::new())?;
//! let res = sender.send_request(req).await?;
//! ```
//!
//! ## Server Example with Axum
//!
//! ```ignore
//! use rats_rs::transport::rustls::{RustlsServerBuilder, ServerTlsStream};
//! use rats_rs::transport::GenericSecureTransPort;
//! use axum::{Router, routing::get};
//! use hyper_util::rt::TokioIo;
//! use hyper::server::conn::http1;
//!
//! let listener = TcpListener::bind("0.0.0.0:8080").await?;
//! let app = Router::new().route("/secret", get(get_secret));
//!
//! loop {
//!     let (stream, addr) = listener.accept().await?;
//!     
//!     // Create and configure the RA-TLS server
//!     let mut server = RustlsServerBuilder::new(stream)
//!         .with_verify_peer(false) // or true for mutual attestation
//!         .with_custom_claims(claims)
//!         .build()
//!         .await?;
//!     
//!     // Perform RA-TLS negotiation (TEE attestation happens here!)
//!     server.negotiate().await?;
//!     
//!     // Take the stream for HTTP use
//!     let tls_stream = server.into_stream()?;
//!     let io = TokioIo::new(tls_stream);
//!     
//!     // Serve with hyper
//!     let service = app.clone();
//!     tokio::spawn(async move {
//!         http1::Builder::new()
//!             .serve_connection(io, service)
//!             .await
//!     });
//! }
//! ```

use crate::cert::verify::verify_cert_der;
use crate::tee::claims::Claims;
use log::{debug, error, info};
use std::sync::Arc;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::client::danger::ServerCertVerified;
use tokio_rustls::rustls::server::danger::ClientCertVerified;
use tokio_rustls::rustls::CertificateError;
use tokio_rustls::rustls::Error;
use tokio_rustls::rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    server::{danger::ClientCertVerifier, WebPkiClientVerifier},
};

pub mod client;
pub mod server;

// Re-export main types
pub use client::{ClientTlsStream, RustlsClient, RustlsClientBuilder};
pub use server::{RustlsServer, RustlsServerBuilder, ServerTlsStream};

// Re-export tokio types for convenience
pub use tokio::net::TcpStream;

/// Callback type for custom verification logic.
/// 
/// The callback receives the extracted claims from the peer's certificate
/// and should return `Ok(())` to accept or `Err(reason)` to reject.
/// 
/// # Example
/// ```ignore
/// let callback: VerifyCallback = Arc::new(|claims| {
///     if let Some(rtmr0) = claims.get("tdx_rt_mr0") {
///         println!("RTMR0: {}", hex::encode(rtmr0));
///     }
///     if let Some(app_id) = claims.get("appId") {
///         println!("AppId: {}", String::from_utf8_lossy(app_id));
///     }
///     Ok(()) // Accept the certificate
/// });
/// ```
pub type VerifyCallback = Arc<dyn Fn(&Claims) -> Result<(), String> + Send + Sync>;

struct RatsClientVerifier {
    default_client_verifier: Arc<dyn ClientCertVerifier>,
    callback: Option<VerifyCallback>,
}

impl std::fmt::Debug for RatsClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatsClientVerifier")
            .field("has_callback", &self.callback.is_some())
            .finish()
    }
}

struct RatsServerVerifier {
    default_server_verifier: Arc<WebPkiServerVerifier>,
    callback: Option<VerifyCallback>,
}

impl std::fmt::Debug for RatsServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatsServerVerifier")
            .field("has_callback", &self.callback.is_some())
            .finish()
    }
}

impl ClientCertVerifier for RatsClientVerifier {
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        self.default_client_verifier.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::server::danger::ClientCertVerified, Error> {
        debug!("Verifying client certificate (RA-TLS)...");
        
        // Verify the certificate and extract claims
        let claims = match verify_cert_der(end_entity.as_ref()) {
            Ok(claims) => {
                info!("Client certificate verification successful!");
                claims
            }
            Err(err) => {
                error!("Client certificate verification failed: {:?}", err);
                return Err(Error::General(format!("Verify failed: {:?}", err)));
            }
        };

        // Call user callback if provided
        if let Some(callback) = &self.callback {
            if let Err(reason) = callback(&claims) {
                error!("Client certificate rejected by callback: {}", reason);
                return Err(Error::General(format!("Rejected by callback: {}", reason)));
            }
            debug!("Client certificate accepted by callback");
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, Error> {
        self.default_client_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, Error> {
        self.default_client_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.default_client_verifier.supported_verify_schemes()
    }
}

impl ServerCertVerifier for RatsServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        debug!("Verifying server certificate (RA-TLS)...");
        
        // Verify the certificate and extract claims
        let claims = match verify_cert_der(end_entity.as_ref()) {
            Ok(claims) => {
                info!("Server certificate verification successful!");
                claims
            }
            Err(err) => {
                error!("Server certificate verification failed: {:?}", err);
                return Err(Error::General(format!("Verify failed: {:?}", err)));
            }
        };

        // Call user callback if provided
        if let Some(callback) = &self.callback {
            if let Err(reason) = callback(&claims) {
                error!("Server certificate rejected by callback: {}", reason);
                return Err(Error::General(format!("Rejected by callback: {}", reason)));
            }
            debug!("Server certificate accepted by callback");
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.default_server_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.default_server_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.default_server_verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod test {}
