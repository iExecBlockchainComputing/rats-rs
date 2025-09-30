# rats-rs Project Introduction

This document mainly introduces the overall architecture of the rats-rs project and the functions of each module.

## Overall Architecture

The architecture diagram of this project is shown in the figure below.

![](rats-rs-architecture.svg)

In the initial design of this project, modularization was considered as much as possible. The upper modules in the figure have calling dependencies on the lower modules, while there are no dependency relationships between modules at the same level.

In addition, each module generally abstracts corresponding `trait` types and makes full use of generics and composite design patterns to achieve generality. In some aspects, the features mechanism in Cargo.toml is used for conditional compilation to achieve functionality trimming.

The top layer in the figure is the application layer, and corresponding examples can be found [here](/examples/spdm). It is worth mentioning that rats-rs exposes three different levels of API interfaces for upper-level applications, from high to low:

- **Secure Session Layer API**: The most commonly used API, which can provide upper-level applications with the ability to establish secure sessions based on remote attestation guarantees.
- **X.509 Certificate Layer API**: This API exposes the generation and verification interfaces of X.509 certificates with remote attestation attributes, suitable for scenarios that require X.509 certificates but have customized requirements for their usage.
- **Remote Attestation Primitive API**: This API allows users to use the remote attestation capabilities provided by TEE instances in a unified way, including Evidence data acquisition and verification.

## Module Functions

This project currently mainly includes the following modules:

### Remote Attestation Primitives

This module contains the remote attestation and verification logic corresponding to different TEE types. In this module, the project provides abstractions for different TEE types, including `Attester`, `Verifier`, `Evidence`, `Claims`, etc. The corresponding trait design is as follows:

```rust
/// Trait representing generic evidence.
pub trait GenericEvidence: Any {
    /// Return the CBOR tag used for generating DICE cert.
    fn get_dice_cbor_tag(&self) -> u64;

    /// Return the raw evidence data used for generating DICE cert.
    fn get_dice_raw_evidence(&self) -> &[u8];

    /// Return the type of Trusted Execution Environment (TEE) associated with the evidence.
    fn get_tee_type(&self) -> TeeType;

    /// Parse the evidence and return a set of claims.
    fn get_claims(&self) -> Result<Claims>;
}

/// Trait representing a generic attester.
pub trait GenericAttester {
    type Evidence: GenericEvidence;

    /// Generate evidence based on the provided report data.
    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence>;
}

/// Trait representing a generic verifier.
pub trait GenericVerifier {
    type Evidence: GenericEvidence;

    /// Verifiy the provided evidence against the given report data.
    fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &[u8],
    ) -> Result<()>;
}

pub type Claims = IndexMap<String, Vec<u8>>;

```

Each TEE type only needs to provide the corresponding implementation of the trait to work collaboratively with other components in the project through composition.

For upper-level applications that are not sensitive to the specific TEE type used, we also provide `AutoAttester` and `AutoVerifier` types to achieve automatic adaptation to different TEE type implementations. This type can automatically determine the TEE type in the current runtime environment, thus shielding upper-level applications from TEE-specific code.

> This project also provides the ability to trim the TEE types supported by the project at compile time in the form of features. These capabilities are controlled by features named in the format of `attester-*` and `verifier-*` in Cargo.toml.

### Cryptographic Algorithms

This module provides abstract interfaces for cryptographic primitives, mainly including support for various Hash functions and public key cryptographic algorithms. Like the remote attestation primitives, this module is also one of the very basic capabilities in the project and will be called by other modules such as the X.509 certificate layer and secure session layer.

For convenience and to reduce coupling between modules, this module uses enum polymorphism to encapsulate algorithms of the same type and provides consistent functional interfaces externally.

Currently supported Hash functions:
- SHA-256
- SHA-384
- SHA-512

Supported public key cryptographic algorithms:
- RSA-2048
- RSA-3072
- RSA-4096
- NIST P-256 (secp256r1)

In addition, this module also allows choosing the implementation backend of these cryptographic algorithms, which provides more friendly options for scenarios with strict performance and resource constraints. The current backend implementation is based on [RustCrypto](https://github.com/RustCrypto) (controlled by the `crypto-rustcrypto` feature). Future implementations based on [ring](https://github.com/briansmith/ring) or [rust-openssl](https://github.com/sfackler/rust-openssl) will also be considered.

### X.509 Certificate Layer

This module mainly provides the implementation of certificate generation and certificate verification logic, exposing two interfaces: `CertBuilder` and `CertVerifier`.

This project refers to the [Interoperable RA-TLS](https://github.com/CCC-Attestation/interoperable-ra-tls) draft and designs a self-signed certificate mode that combines remote attestation Evidence and X.509 certificates, which we simply call DICE certificates. The specific details are described in [this](/docs/core-design-of-cpu-spdm.md) document.

### Transport Layer

The transport layer module mainly serves the secure session layer, because the data transmission of the secure session layer needs to be built on top of the transport layer, so it can be regarded as a relatively simple thin layer.

Specifically, for the scenario where the secure session layer runs the SPDM protocol, the transport layer needs to establish a bridge between the communication capabilities provided by the operating system and the SPDM protocol implementation. That is, to implement the corresponding `SpdmDeviceIo` interface in spdm-rs for these different communication methods.

SPDM protocol data packets are individual packets. In order for the SPDM protocol to be carried on existing stream-based transport layers (such as TCP, Unix domain Socket, Pipe, etc.), a framing scheme needs to be provided to transmit Packets in Streams. For this purpose, we provide a simple framing implementation `FramedStream`, as shown in the figure below.

```txt
 ┌──────────┬────────────────────────┐ 
 │   Size   │         Packet         │ 
 │ (4Bytes) │   (arbitrary length)   │ 
 └──────────┴────────────────────────┘ 
```

Where `Packet` is the SPDM packet generated and consumed by the secure session layer. When parsing the Stream, the 4-byte Size field is encountered first, indicating the length of the Packet. This field is placed in front of each Packet, followed by the specific content of the Packet.

The design of the `FramedStream` type is roughly as follows:

```rust
/// `FramedStream` is a generic framing module that segments a stream of `u8` data (`S`)
/// into multiple packets. It maintains an internal state to manage reading from the stream
/// and buffers data until complete packets are formed.
pub struct FramedStream<S: Read + Write + Send + 'static> {
    pub(crate) stream: S,
    read_buffer: Vec<u8>,
    read_remain: usize,
}

#[maybe_async::maybe_async]
impl<S> SpdmDeviceIo for FramedStream<S>
where
    S: Read + Write + Send + 'static,
{
    /* ... */
}
```

With the help of generics, we can provide the ability to carry the secure session layer on all Stream types that implement `Read + Write + Send + 'static` (such as TcpStream). This design brings convenience to upper-level applications.

### Secure Session Layer

The secure session layer module aims to provide the implementation of arbitrary secure transport layers built on remote attestation. To achieve this goal, this module provides the following abstract interfaces:

```rust
#[maybe_async]
pub trait GenericSecureTransPort {
    async fn negotiate(&mut self) -> Result<()>;
}

#[maybe_async]
pub trait GenericSecureTransPortWrite {
    async fn send(&mut self, bytes: &[u8]) -> Result<()>;

    async fn shutdown(&mut self) -> Result<()>;
}

#[maybe_async]
pub trait GenericSecureTransPortRead {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize>;
}
```

This covers the four basic capabilities that the secure session layer needs to provide externally: handshake negotiation, receiving data, sending data, and closing sessions. Currently, it includes SPDM protocol support and can complete the above four basic capabilities.

#### SPDM Secure Session

The core implementation of the SPDM protocol is based on the [spdm-rs](https://github.com/ccc-spdm-tools/spdm-rs) project. On the basis of this project, we implemented the integration with the remote attestation process and provided simple encapsulation of Requester and Responder roles for upper-level applications.

In spdm-rs, there is an SPDM transport layer (`trait SpdmTransportEncap`) interface that specifies how to encode and decode SPDM protocol Packets. spdm-rs itself provides two different implementations: PCI-DOE and MCTP. However, this implementation is tightly coupled with other parts of the PCI-DOE protocol and MCTP protocol definitions and is designed for communication between CPU and peripherals. For this reason, for general TEE interconnection scenarios, we provide a similar `struct SimpleTransportEncap` implementation. The Packet structure generated by this message encoding method is as follows:

```txt
 ┌──────────┬────────────────────────┐ 
 │   Type   │        Message         │ 
 │ (1 Byte) │   (arbitrary length)   │ 
 └──────────┴────────────────────────┘ 
```

The Type field is defined as an enum type as follows:

```rust
enum_builder! {
    /// Enumeration of message types for the Transport Message.
    @U8
    EnumName: SimpleTransportMessageType;
    EnumVal{
        /// Message type for SPDM messages.
        Spdm => 0x00,
        /// Message type for Secured messages. The plaintext is either an SDPM message or an APP message.
        Secured => 0x01,
        /// Message type for APP messages.
        App => 0x02
    }
}
```

We use a 1-byte `u8` tag to distinguish between three types of messages: SPDM messages, protected SPDM messages, and APP messages.

Basically, we will encounter three types of Packets:

1. Unencrypted SPDM messages, commonly seen in the SPDM handshake phase when the Session has not been established yet.

    ```txt
    ┌──────────┬────────────────────────┐ 
    │   Spdm   │        Payload         │ 
    │  (0x00)  │     (Spdm message)     │ 
    └──────────┴────────────────────────┘ 
    ```

2. Encrypted SPDM messages, commonly seen during SPDM sessions when the Session has been established, and the Payload contains messages that have been encrypted and integrity-protected using the negotiated session key.

    ```txt
    ┌──────────┬────────────────────────┐ 
    │  Secured │        Payload         │ 
    │  (0x01)  │ (Encrypted SPDM Packet)│ 
    └──────────┴────────────────────────┘ 
    ```
    Depending on the different content of encrypted messages in the Payload, it can be subdivided into two situations:

    - The plaintext of the encrypted message is an SPDM message, such as KEY_UPDATE and other messages

        ```txt
        ┌──────────┬────────────────────────┐ 
        │   Spdm   │        Payload         │ 
        │  (0x00)  │     (Spdm message)     │
        └──────────┴────────────────────────┘ 
        ```

    - The plaintext of the encrypted message is an APP message, and its content is arbitrary data that the upper-level application wants to transmit.

        ```txt
        ┌──────────┬────────────────────────┐ 
        │   App    │        Payload         │ 
        │  (0x02)  │    (arbitrary data)    │
        └──────────┴────────────────────────┘ 
        ```

For security reasons, Packets that do not fall into the above categories or fail to decode ciphertext are considered illegal messages.

### Modifications to the spdm-rs Project

Due to some gaps between the implementation code of the spdm-rs project and the design goals of this project, we forked and modified the spdm-rs project for customization. The main modifications include:

1. To provide more convenient data sending and receiving interfaces for upper-level applications, we adjusted the logic of spdm-rs when processing APP messages (app_message) in `ResponderContext::process_message()`. We removed the `SpdmAppMessageHandler` callback function that we don't need.

2. Rewrite the callback logic in spdm-rs, removing some global, C-like function pointer callback implementations and abstracting key parts into trait interfaces.

    Specifically, we added 4 additional traits from spdm-rs and provided corresponding implementations of these traits based on other modules in this project:

    - `trait SecretAsymSigner`: The private key and signature logic of the SPDM communication party, which will be used to complete the signature of given data in multiple messages during the SPDM negotiation phase. In the corresponding implementation, random keys generated by the X.509 certificate layer are used, and the signature logic implementation of the cryptographic algorithm layer is called.

    - `trait CertProvider`: The certificate provision logic of the SPDM communication party, which is used for identity verification on the Responder side. This part uses the CertBuilder implementation of the X.509 certificate layer.

    - `trait CertValidationStrategy`: The logic for verifying certificates sent by the peer in SPDM communication. This part uses the CertVerifier implementation of the X.509 certificate layer.

    - `trait MeasurementProvider`: Provides the measurements needed in SPDM communication, which is implemented using the functionality of the remote attestation primitive layer.

3. Fix several logical errors in the spdm-rs project.

The above changes to spdm-rs will not affect the interaction method and message format design of the SPDM protocol.

### User Interface

This module also encapsulates the overall protocol flow and provides two interfaces: `SpdmRequesterBuilder` and `SpdmResponderBuilder`, making it easier for upper-level applications to establish SPDM sessions. For specific usage, please refer to the [sample programs](/examples/spdm).

> It is worth mentioning that the goal of this project is not limited to providing SPDM protocol support. In the future, it can also be extended to provide secure session layers based on protocols such as TLS and DTLS.
