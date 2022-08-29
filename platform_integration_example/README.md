# Platform Integration Example

This is an example of a platform integration which can be used on unix
systems relying on
the [select](https://en.wikipedia.org/wiki/Select_(Unix)) method for
event notifications on sockets. The select abstraction is also found
on numereous embedded systems so this example can be used as an base
for such integrations.

The example creates a library which implements the of the
`nabto/nabto_device.h` API.

## Overall architecture.

An application e.g. a Thermostat Device is using the API described in
the header file `nabto/nabto_device.h`. The thermostat is linked against
the library e.g. `libnabto_device.so` (`nabto_device` library).

This platform integration example is all about creating the
`nabto_device` library.

The architecture of the `nabto_device` library is as follows. The
functions which is decribed in the header file `nabto/nabto_device.h`
is implemented in several files in the folder `src/api/` (API). The
API primarily uses the core `src/core`, some threads
`src/api/nabto_device_threads.h` and the
`src/api/nabto_device_platform.h` to implements the nabto_device
library.

## Components which is needed for a custom platform.

To create the `nabto_device` library several things needs to be
implemented.

### `api/nabto_device_platform.h`

This file contains 3 functions, an init, deinit and a stop
function. These functions is called when a device is created,
destroyed and stopped. The purpose of these functions is to setup the
`platform/np_platform.h` (described later) and to create the overall functionality which
is required to run such a platform. That could include threads to run
the networking and the event queue. The actual initialization of the platform happens from the
`nabto_device_init_platform` function. See `doc/np_platform.md` and the header file for further
information.

### `platform/np_platform.h`

The first is the `platform/np_platform.h` platform. This contains all
the core functionality that is needed for Nabto Edge to run on a specific platform.
The platform consists of several independent modules encapsulated in struct's.
Each struct consists of a list of function pointers that needs to be setup in the bootstrap process of 'nabto_device_init_platform'.

Each module in `np_platform.h` should be implemented or an implementation which
is working on the desired platform should be choosen. This example works on UNIX systems so
modules which works on such a system has been choosen.



### `api/nabto_device_threads.h`

The api `nabto/nabto_device.h` is a thread safe API, which also
exposes functionality which can block the system. So the api
implementation needs to have a thread implementation. The thread
abstraction defindes, threads, mutexes and condition variables. See
the header file for more information or take a look at the existing
implementations in the `src/modules/threads` folder.
