# nabto-embedded-sdk

Nabto embedded SDK

## Building and Testing

```
mkdir _build
cd _build
cmake -DCMAKE_INSTALL_PREFIX=../_install ..
cmake --build . --config Release --target install
../_install/bin/embedded_unit_test -p
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

This folder contains applications which can be used as they are.

### `platform_integration_example`

This folder contains an example of a custom implementation of the
`nabto/nabto_device.h` api.

### `include`

This folder has the public interface which the nabto_device api
exposes.
