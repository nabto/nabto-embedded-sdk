# Nabto Edge Embedded SDK

The Nabto Edge platform makes it possible to communicate _directly_ between two entities: Instead of interacting indirectly with a device through a cloud service, the platform makes it simple to communicate directly with the actual device to invoke services or transfer data - also through firewalls. Read more on [docs.nabto.com](https://docs.nabto.com/developer/guides/overview/platform-overview.html)!

See the [general introduction](https://docs.nabto.com/developer/platforms/embedded/intro.html) to the Nabto Edge Embedded SDK for an overview and more information.

## Obtaining the Source

The full Nabto Edge Embedded SDK [source code](https://github.com/nabto/nabto-embedded-sdk) is available for simple integration (commercial license).

The Github repo references various 3rd party components as submodules. So remember to clone recursively:

```
git clone --recursive https://github.com/nabto/nabto-embedded-sdk.git
```

Or download a full source bundle (`nabto-embedded-sdk.zip`) from the [latest release](https://github.com/nabto/nabto-embedded-sdk/releases/latest). This bundle contains all dependencies - and should not be confused with the "Source code" bundle automatically generated by Github that does not contain dependencies.

## Building and Testing

The Nabto Edge Embedded SDK can be built using [CMake](https://cmake.org/). The instructions below assume the `cmake` tool is installed and available.

To build the SDK, a C99 compatible compiler is required (see [Supported environments](#supported-environments)).

To build the SDK's unit tests, a C++ compiler is required. If the SDK is built for a target without a C++ compiler, CMake will detect the missing compiler and disable building the unit tests. Building of tests can also be disabled manually (see below).

### Building

The following builds using the default compiler on the build platform:

```
mkdir _build
cd _build
cmake -DCMAKE_INSTALL_PREFIX=../_install ..
cmake --build . --config Release --target install
```

To do a cross build, set the `CC` environment variable to point to the cross compiler prior to the above steps, for instance:

```
export CC=/opt/hisi-linux-nptl/arm-hisiv100-linux/target/bin/arm-hisiv100-gcc
```

If no C++ compiler is available, CMake _should_ detect this and disable building the C++ based unit
tests. If this detection fails and the unit test build fails, building the tests can be disabled manually by modifying the
first `cmake` commandline (the configuration step) above as follows:

```
cmake -DDEVICE_BUILD_TESTS=Off -DCMAKE_INSTALL_PREFIX=../_install ..
```

### Testing

If build passed, and `DEVICE_BUILD_TESTS` is set to `ON` unit tests can be run.

```
../_install/bin/embedded_unit_test -p
```

If the build was successful but unit tests was not build, an example application can be run to validate the Embedded SDK can run.


### Building for Embedded Systems

See the [supported platforms](https://docs.nabto.com/developer/platforms.html) page for build instructions for existing supported embedded platforms. And the [Integration guide](https://docs.nabto.com/developer/guides/integration/intro.html) to see how to port to a new platform.


### WolfSSL

By default, the Embedded SDK uses the MbedTLS library for DTLS operations. In addition, the Embedded SDK also comes with a module using the WolfSSL library. Switching to the Wolfssl module is done with the CMake option `NABTO_DEVICE_WOLFSSL`:

```
cmake -DNABTO_DEVICE_WOLFSSL=ON -DCMAKE_INSTALL_PREFIX=../_install ..
```

If not using CMake, compiler definitions of the same names can be used through `includes/nabto/nabto_device_config.h`.

MbedTLS source files are included as a 3rdparty submodule on this repo. However, using the WolfSSL library requires the library to be installed on the system.

Nabto is currently tested with wolfssl 5.5.1

https://github.com/wolfSSL/wolfssl/releases/tag/v5.5.1-stable

When installing WolfSSL, the following build options can be used:

```
./configure --prefix=/usr --enable-ecc --enable-dsa --enable-dtls --enable-aesccm --enable-alpn --enable-debug --enable-certgen --enable-keygen --enable-harden --enable-sni --enable-sp-math-all=small CFLAGS="-DKEEP_PEER_CERT -DWOLFSSL_PUBLIC_MP -DWOLFSSL_PUBLIC_ECC_ADD_DBL"
```

## Overview

An application using this SDK is going to use the `nabto_device`
library. The interface for that library is described in
`include/nabto/nabto_device.h` This repository both contains code
which implements the `nabto_device` library and apps/examples which
are using the `nabto_device` library.

For help on porting of the `nabto_device.h` interface to a new platform, see the Nabto Edge Embedded
SDK [Integration guide](https://docs.nabto.com/developer/guides/integration/intro.html).

For details on using the Nabto IAM module for user access control and
management, see `src/modules/iam/README.md`. Also see the general [Nabto Edge IAM Introduction](https://docs.nabto.com/developer/guides/iam/intro.html).


## Structure of this repository

The source is split into several parts.

### `src/api`

This is an implementation of the thread/mutex based device api defined
in `<nabto/nabto_device.h>`.

### `src/api_test`

This folder contains tests programs which can be used from the api
layer. The tests is implementation of the test functions found in
`<nabto/nabto_device_test.h>`. The idea is that these tests can
be run on a custom platform integration for the `<nabto/nabto_device.h>`
API.

### `src/platform/interfaces`

The platform interfaces folder contains platform interfaces for
functionality like TCP, UDP, DNS, Event Queue, Timestamps, etc.

### `src/platform`

The platform folder contains some utility functions and wrappers for
the interfaces defined in `src/platform/interfaces`

### `src/core`

The core functionality of the Nabto Edge device is implemented
here. This implements the communication protocols and inner working of
the device, like connection management.

### `src/modules`

Modules is the folder where modules for specific targets
exists. Modules can be for IAM, encryption, networking, timing, logging
etc.

### `src/nabto_device_libevent`

This is the default implementation of the `<nabto/nabto_device.h>` API
for Linux, Windows and Mac. The implementation relies on libevent as
the name suggests.

### `nabto-common`

This folder contains some common functionality which is shared amongst
several components.

### `3rdparty`

This folder contains 3rdparty functionality. Either as submodules or
code which is copied for simplicity.

### `examples`

This folder contains examples for how the platform can be used.

### `apps`

This folder contains production ready applications which can be used
as they are.

### `platform_integration_example`

This folder contains an example of a custom implementation of the
`nabto/nabto_device.h` api.

### `include`

This folder has the public interface which the nabto_device api
exposes.


## Supported environments

The code is meant to be runnable in most relevant environments, it is tested and
run on the most popular gcc, clang and msvc environments. If the code does not
compile for a relevant embedded target which should be supported, contact our
support. The code is not strictly C89 it uses several features from C99 which
are broadly supported by many C compilers.

## Stack usage

The code has been made for embedded systems without huge stacks. An actual stack
usage needs to be measured by the application. The actual stack usage depends on
how the nabto embedded SDK is configured and which features are enabled and used.

# Validate the correctness of the code

## Test that all allocated memory are freed and that memory access is sane.

For this valgrind is a good tool. All the code which is meant to be run in
production is free from memory leaks. Some of the test code can leak a bit. But
it should not leak as it makes finding leaks in the production code harder.

## Test how allocation errors are handled.

We use the tool mallocfail `https://github.com/nabto/mallocfail` to test that
all callstacks leading to a failing dynamic allocation is handled properly.

```
MALLOCFAIL_DEBUG=1 LD_PRELOAD=~/sandbox/mallocfail/mallocfail.so ./build/apps/tcp_tunnel_device/tcp_tunnel_device
```

MbedTLS uses a large number of allocation, thats why it is often a good idea to
just ignore these by adding the environment variable
`MALLOCFAIL_IGNORE=mbedtls`.

## Test for race conditions and similar threading errors.

For this the valgrind tool helgrind is good.
```
valgrind --tool=helgrind ./build/apps/tcp_tunnel_device/tcp_tunnel_device
```
