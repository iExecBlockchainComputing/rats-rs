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

use crate::cert::verify::CertVerifier;
use crate::cert::verify::VerifiyPolicy::Contains;
use crate::cert::verify::VerifyPolicyOutput;
use crate::tee::claims::Claims;
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

#[derive(Debug)]
struct RatsClientVerifier {
    default_client_verifier: Arc<dyn ClientCertVerifier>,
}

#[derive(Debug)]
struct RatsServerVerifier {
    default_server_verifier: Arc<WebPkiServerVerifier>,
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
        let res = CertVerifier::new(Contains(Claims::new())).verify(&end_entity);
        match res {
            Ok(VerifyPolicyOutput::Passed) => {
                return Ok(ClientCertVerified::assertion());
            }
            Ok(VerifyPolicyOutput::Failed) => {
                return Err(Error::General(
                    "Verify failed because of claims".to_string(),
                ));
            }
            Err(err) => {
                return Err(Error::General(
                    format!("Verify failed with err: {:?}", err).to_string(),
                ));
            }
        }
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
        let res = CertVerifier::new(Contains(Claims::new())).verify(&end_entity);
        match res {
            Ok(VerifyPolicyOutput::Passed) => {
                return Ok(ServerCertVerified::assertion());
            }
            Ok(VerifyPolicyOutput::Failed) => {
                return Err(Error::General(
                    "Verify failed because of claims".to_string(),
                ));
            }
            Err(err) => {
                return Err(Error::General(
                    format!("Verify failed with err: {:?}", err).to_string(),
                ));
            }
        }
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
