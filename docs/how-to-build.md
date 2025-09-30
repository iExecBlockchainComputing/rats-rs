# Building

## Environment Setup

### Docker

This project provides a build development environment in the form of Docker containers. You can use the following command to pull the build development environment image.

```sh
docker pull ghcr.io/inclavare-containers/rats-rs:master
```

Or you can build directly using the Dockerfile

```sh
git clone git@github.com:inclavare-containers/rats-rs.git
cd rats-rs
docker build --tag rats-rs:master .
```

Then, depending on the TEE type, use the corresponding command to start the environment:

- SGX instance:

    ```sh
    docker run -it --privileged --device=/dev/sgx_enclave --device=/dev/sgx_provision rats-rs:master bash
    ```

- TDX instance:

    ```sh
    docker run -it --privileged --device=/dev/tdx_guest rats-rs:master bash
    ```

### Manual Dependency Installation

The following provides the dependency installation process on Ubuntu 22.04. The process on other distributions is similar and can be referenced from [Intel_SGX_SW_Installation_Guide_for_Linux.pdf](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf).

1. Install basic dependency libraries

    ```sh
    echo "deb http://cn.archive.ubuntu.com/ubuntu bionic main" >> /etc/apt/sources.list
    apt-get update
    apt-get install -y libprotobuf10 make git vim clang-format-9 gcc \
        pkg-config protobuf-compiler debhelper cmake \
        wget net-tools curl file gnupg tree libcurl4-openssl-dev \
        libbinutils libseccomp-dev libssl-dev binutils-dev libprotoc-dev \
        clang jq
    ```

2. Install Rust toolchain

    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    ```
    Add the following statement to the end of `~/.bashrc`
    ```sh
    export PATH=/root/.cargo/bin:$PATH
    ```

    (Optional) Install `llvm-tools-preview` for code coverage calculation
    ```
    rustup component add llvm-tools-preview
    ```

3. This project uses the [just](https://github.com/casey/just/) tool to encapsulate the build, test, and run processes of this project, so just needs to be installed first.

    ```sh
    cargo install just
    ```

4. Install Intel SGX LVI mitigated toolchain

    ```sh
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/as.ld.objdump.r4.tar.gz && \
        tar -zxvf as.ld.objdump.r4.tar.gz && cp -rf external/toolset/ubuntu20.04/* /usr/local/bin/ && \
        rm -rf external && rm -rf as.ld.objdump.r4.tar.gz
    ```

5. Install Intel SGX SDK

    > Depends on Intel SGX SDK version >= 2.23

    ```sh
    SGX_SDK_VERSION=2.23
    SGX_SDK_RELEASE_NUMBER=2.23.100.2
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/distro/ubuntu20.04-server/sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        chmod +x sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        echo -e 'no\n/opt/intel\n' | ./sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin
    ```

6. Install SGX DCAP software packages

    Add Intel's official online apt repo

    ```sh
    echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee /etc/apt/sources.list.d/intel-sgx.list && \
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
    apt-get update -y
    ```

    Install SGX DCAP software packages

    ```sh
    SGX_SDK_VERSION=2.23
    SGX_DCAP_VERSION=1.20
    apt-get update -y && apt-get install -y libsgx-headers="$SGX_SDK_VERSION*" \
        libsgx-uae-service="$SGX_SDK_VERSION*" \
        libsgx-dcap-quote-verify-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-ql-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-default-qpl-dev="$SGX_DCAP_VERSION*"
    ```

7. Install occlum, used to run rats-rs sample programs in the occlum environment

    ```sh
    echo 'deb [arch=amd64] https://occlum.io/occlum-package-repos/debian focal main' | tee /etc/apt/sources.list.d/occlum.list
    wget -qO - https://occlum.io/occlum-package-repos/debian/public.key | apt-key add -
    apt-get update
    apt-get install -y libfuse2 occlum occlum-toolchains-glibc
    ```

    Add the following statement to the end of `~/.bashrc`

    ```sh
    export PATH="/opt/occlum/build/bin:${PATH}"
    ```

8. (For TDX instances) Install TDX Attestation library
    ```sh
    SGX_DCAP_VERSION=1.20
    apt-get install -y libtdx-attest-dev="$SGX_DCAP_VERSION*"
    ```

## Building

If you are preparing to build this project separately or simply try the sample programs provided in this project, you can use the following method to build the code:

1. Pull the source code
    
    ```sh
    git clone git@github.com:inclavare-containers/rats-rs.git
    cd rats-rs
    ```

2. Prepare

    ```sh
    just prepare-repo
    ```

3. Build the project

    ```sh
    cargo build
    ```

4. (Optional) Build sample programs

    ```sh
    cargo build -p spdm
    ```

    For how to run sample programs, please refer to the [examples](/examples/spdm) in the examples directory.
