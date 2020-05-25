# nabto-embedded-sdk

Nabto embedded SDK

## Building and Testing

mkdir `build_dir`
cd `build_dir`
cmake ..
make
`./test_cpp/embedded_unit_test`


## Overview

An application using this SDK is going to use the `nabto_device`
library. The interface for that library is described in
`include/nabto/nabto_device.h` This repository both contains code
which implements the `nabto_device` library and apps/examples which
are using the `nabto_device` library.

## Parts of this repository

The source is split into several parts.

### `src/platform`

The platform folder contains a platform which is used to run the
core. The platform contains functionality for things like UDP, TCP,
timestamps, DNS resolution, DTLS, etc. See
`src/platform/np_platform.h` for futher information.

### `src/core`

The core is the nabto communication protocol, the core uses the
platform and implements the core of the embedded nabto communication
system.

### `src/modules`

Modules is the folder where modules for specific targets
exists. Modules can be for encryption, networking, timing, logging
etc.

### `nabto-common`

This folder contains some common functionality which is shared amongst
several components.

### `3rdparty`

This folder contains 3rdparty functionality. Either as submodules or
code which is copied for simplicity.

### `examples`

This folder contains examples for how the platform can be used.

### `apps`

This folder contains applications which can be used as they are.

### `platform_integration_example`

This folder contains an example of a custom implementation of the
`nabto/nabto_device.h` api.

### `include`

This folder has the public interface which the nabto_device api
exposes.
