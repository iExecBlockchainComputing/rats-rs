# spdm

This directory contains a sample program `spdm` for demonstrating how upper-level applications use rats-rs for development. It mainly covers examples of secure communication using remote attestation and SPDM protocols provided by rats-rs.

The sample program `spdm` currently covers two examples: `spdm-echosvr` and `spdm-tunnel`. To reduce code duplication, these two examples are integrated into different subcommands of the same sample program. The usage of these two examples will be introduced separately below.

## Building

First, refer to the [build documentation](/docs/how-to-build.md) to complete the build environment setup. We recommend using Docker containers directly to quickly establish a build environment.

Next, use the following command to build this sample program:
```sh
cargo build -p spdm
```

You can use the `target/debug/spdm --help` command to view the command-line parameters of this sample program:
```txt
Usage: spdm <COMMAND>

Commands:
  echo-server    
  echo-client    
  tunnel-server  
  tunnel-client  
  help           Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## spdm-echosvr

This example demonstrates how to create an SPDM secure communication shell running on TCP streams and communicate within it. It corresponds to the `echo-server` and `echo-client` subcommands in the sample program `spdm`, which represent the server and client sides respectively.

After establishing an SPDM session with the server, the client continuously generates random data and sends it to the server, and then the server sends the data back to the client. This aims to demonstrate the ability to implement bidirectional secure data transmission guaranteed by remote attestation using rats-rs.

This program supports running in non-TEE environments, SGX-based Occlum environments, and TDX virtual machine environments. The following provides a simple running method in the Occlum environment. More detailed parameters can be learned by specifying the `--help` option.

1. Run the server in Occlum

    ```sh
    just run-in-occlum echo-server --attest-self --listen-on-tcp 127.0.0.1:8080
    ```
> [!IMPORTANT]  
> The `--attest-self` option specifies that the server needs to act as an attester to prove its identity to the peer. When this option is specified, it must be run in some TEE environment.

2. Run the client

    This example uses one-way remote attestation, so the client does not need to prove its identity to the peer. Therefore, it can run in either a non-TEE environment or a TEE environment.

    For example, running in a non-TEE environment:
    ```sh
    just run-in-host echo-client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

    Or, running in an Occlum environment:
    ```sh
    just run-in-occlum echo-client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

> [!NOTE]
> You can use the environment variable `RATS_RS_LOG_LEVEL` to control the log level enabled by this program. The environment variable values are `error`, `warn`, `info`, `debug`, and `trace`, with the default value being `trace`.

## spdm-tunnel

For scenarios where you don't want to modify business code at all, or don't have the source code of business programs, but still want to introduce secure communication capabilities, you can solve this need by establishing a tunnel. This example demonstrates the ability to establish TCP forwarding between TEE instances and non-TEE instances.

This example also includes server and client sides, corresponding to the `tunnel-server` and `tunnel-client` subcommands in the sample program `spdm`.

![tunnel](src/tunnel/tunnel.svg)

1. Run an nginx service in a TDX instance to simulate a business service program running in a TDX instance in a business scenario.

    ```sh
    nginx -c `realpath ./examples/spdm/src/tunnel/nginx.conf`
    ```

    This nginx will listen on port `9091` and expose a default nginx page.

2. Run the server in the TDX instance

    ```sh
    just run-in-host tunnel-server --attest-self --listen-on-tcp 127.0.0.1:8080 --upstream 127.0.0.1:9091
    ```
    This program will listen for requests from clients on `127.0.0.1:8080` and forward data from the SPDM secure session to the upstream nginx service at `127.0.0.1:9091`.

3. Run the client in a non-TEE environment

    ```sh
    just run-in-host tunnel-client --verify-peer --connect-to-tcp 127.0.0.1:8080 --ingress 127.0.0.1:9090
    ```

    This program will listen for TCP connection requests from business clients (such as browsers) on `127.0.0.1:9090` and forward the data through the SPDM secure session to the upstream `127.0.0.1:8080` spdm-tunnel server.

4. Start a browser in a non-TEE environment to access `http://127.0.0.1:9090/`, or use `curl http://127.0.0.1:9090/` for testing. You will observe that the browser correctly displays the nginx default page content.
