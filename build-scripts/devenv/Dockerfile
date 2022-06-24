FROM ubuntu:22.04

ARG CMAKE_VERSION=3.19.6
ARG WOLFSSL_VERSION=5.3.0-stable

RUN apt update && apt install -y git build-essential autoconf libtool pkg-config wget bash-completion vim gdb clang gcc curl ninja-build valgrind python3-pip sudo unzip

RUN pip3 install cmakelang

WORKDIR /tmp
RUN wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz
RUN tar xf cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz  -C /usr --strip-components=1

WORKDIR /build/wolfssl
RUN wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}.tar.gz
RUN tar xf v${WOLFSSL_VERSION}.tar.gz
WORKDIR /build/wolfssl/wolfssl-${WOLFSSL_VERSION}
RUN ./autogen.sh
# Fastest base intel config ./configure --enable-intelasm --enable-aesni --enable-fpecc --enable-fasthugemath --enable-sp-asm --enable-sp
# Test config modifications with ./wolfcrypt/benchmark/benchmark -ecc
#  Intel(R) Core(TM) i7-8550U results
#------------------------------------------------------------------------------
# wolfSSL version 4.7.1
#------------------------------------------------------------------------------
#wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
#ECDHE [      SECP256R1]   256 agree       53900 ops took 1.001 sec, avg 0.019 ms, 53859.332 ops/sec
#ECDSA [      SECP256R1]   256 sign        52300 ops took 1.000 sec, avg 0.019 ms, 52288.917 ops/sec
#ECDSA [      SECP256R1]   256 verify      46500 ops took 1.001 sec, avg 0.022 ms, 46475.512 ops/sec
#Benchmark complete
# in 4.7.0-stable there is a bug regarding --enable-fpecc in the benchmark on virtual machines so it has been disabled.
RUN ./configure --prefix=/usr --enable-ecc --enable-dsa --enable-dtls --enable-aesccm --enable-alpn --enable-debug --enable-certgen --enable-keygen --enable-harden --enable-sni CFLAGS="-DWOLFSSL_STATIC_RSA -DHAVE_DSA -DHAVE_ALL_CURVES -DHAVE_ECC -DKEEP_PEER_CERT"

RUN make -j 8
RUN ./wolfcrypt/benchmark/benchmark -ecc
RUN make install

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
WORKDIR /workspace/build
