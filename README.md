# rats-rs
[![Testing](/../../actions/workflows/build-and-test.yaml/badge.svg)](/../../actions/workflows/build-and-test.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


rats-rs is a pure Rust implementation of a TEE remote attestation library. Its ultimate goal is to enable developers to easily integrate remote attestation capabilities into various aspects of their applications. It also includes a secure session layer implementation based on the SPDM protocol, which can provide a TLS-like secure encryption layer for communication with TEE environments.

## Key Features
<!-- Key features -->

- Pure Rust implementation
- Easy-to-use Builder Pattern API
- Extensibility for different TEE types
- Three levels of API for upper-level applications
- Support for specifying cryptographic algorithms used by certificates
- Automatic detection of current runtime TEE type
- Feature-based functionality trimming

## Supported TEE Types
<!-- Supported TEE types -->

This project adopts a modular design in supporting different TEE types. The current support status for different TEE types is as follows:

| SGX DCAP(Occlum) | TDX | SEV-SNP | CSV | CCA |
|------------------|-----|---------|-----|-----|
| ✔️               | ✔️  | 🚧      | 🚧  | 🚧  |


## Quick Start
<!-- Quick start -->

The following workflow will guide you through running the rats-rs sample program spdm-echosvr on an SGX instance. The source code can be found [here](/examples/spdm/).

1. First, prepare the rats-rs build environment. It is recommended to use our pre-built Docker container directly

    ```sh
    docker run -it --privileged --device=/dev/sgx_enclave --device=/dev/sgx_provision ghcr.io/inclavare-containers/rats-rs:master bash
    ```

2. Clone the code and compile the sample program
    
    ```sh
    git clone git@github.com:inclavare-containers/rats-rs.git
    cd rats-rs
    
    just prepare-repo

    cargo build -p spdm
    ```

3. Run the server-side program

    ```sh
    just run-in-occlum echo-server --attest-self --listen-on-tcp 127.0.0.1:8080
    ```

4. Run the client-side program (in a new terminal)

    ```sh
    just run-in-host echo-client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

    You will observe the interaction between the Client and Server in the program logs, and you can use the environment variable `RATS_RS_LOG_LEVEL` to control the log level.

    For more details about the sample program, please refer to [this](/examples/spdm/README.md) document.

## Use as a Dependency

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
rats-rs = {git = "https://github.com/inclavare-containers/rats-rs", branch = "master"}
```

To start using the rats-rs API, it is recommended to refer to the [sample programs](/examples/spdm/).

It is also worth mentioning that rats-rs compilation and runtime depend on some system libraries. You can find the complete build environment setup process [here](/docs/how-to-build.md).

## For Developers

This project uses the [just](https://github.com/casey/just/) tool to encapsulate some automation processes, such as testing, running, code coverage calculation, etc. It is very similar to Makefile. When you need to introduce new processes, please try to add them to the [justfile](/justfile).

Before you start coding, you can first read the documentation under [docs](/docs/).

## Project Documentation

Most documents are categorized in the [docs](/docs/) directory. Here are some relatively important documents to facilitate getting started with this project:

- [Environment Setup and Project Build Guide](/docs/how-to-build.md)
- [Testing Guide and Code Coverage](/docs/how-to-run-test.md)
- [Project Architecture and Module Function Description](/docs/architecture-of-the-project.md)
- [CPU-SPDM Protocol Core Design](/docs/core-design-of-cpu-spdm.md)
- [Sample Program Build and Run Instructions](/examples/spdm/README.md)
- [CPU-TEE SPDM Protocol Standardization Document: CPU TEE Secured Messages using SPDM Binding Specification](/docs/CPU%20TEE%20Secured%20Messages%20using%20SPDM%20Binding%20Specification.pdf)


## License

This project is licensed under the Apache License 2.0
