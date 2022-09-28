# Nabto Edge Embedded SDK

The Nabto Edge platform makes it possible to communicate _directly_ between two entities: Instead of interacting indirectly with a device through a cloud service, the platform makes it simple to communicate directly with the actual device to invoke services or transfer data - also through firewalls. Read more on [docs.nabto.com](https://docs.nabto.com/developer/guides/overview/platform-overview.html)!

## Building and Testing

The Embedded SDK unit tests uses Boost C++ unit tests. If the Embedded SDK is build on a target without a C++ compiler, Cmake will detect the missing compiler and disable building the unit tests. Building of tests can also be disabled manually with `cmake -DDEVICE_BUILD_TESTS=Off -DCMAKE_INSTALL_PREFIX=../_install ..`.

### Building
```
mkdir _build
cd _build
cmake -DCMAKE_INSTALL_PREFIX=../_install ..
cmake --build . --config Release --target install
```

### Building on Raspberry Pi

Prerequisite:
  * ssh access to a Raspberry Pi with Raspberry Pi OS read more here https://www.raspberrypi.com/software/

Install tools on the Raspberry Pi

```
sudo apt-get install build-essential cmake git
```

Checkout the source

```
git clone --recursive https://github.com/nabto/nabto-embedded-sdk
```

Build the source
```
cd nabto-embedded-sdk
mkdir build
cd build
cmake ..
make
```

Run the Edge TCP tunnel device
```
./apps/tcp_tunnel_device/tcp_tunnel_device --help
```

### Testing

If build passed, and `DEVICE_BUILD_TESTS` is set to `ON` unit tests can be run.

```
../_install/bin/embedded_unit_test -p
```

If the build was successfull but unit tests was not build, an example application can be run to validate the Embedded SDK can run.

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

For help on porting of the nabto_device.h interface to a new platform
see `doc/platform_integration_howto.md` and
`platform_integration_steps/README.md`

For details on using the Nabto IAM module for user access and
management, see `src/modules/iam/README.md`.


## Parts of this repository

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
