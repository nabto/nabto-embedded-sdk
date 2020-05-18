# API adapters

The device sdk describeded in `nabto/nabto_device.h` is a high level
encapsulation of the features found in the Nabto Edge Embedded SDK. To
support this interface an implementation of the api which is located
in the `src/api` folder is needed. This api needs an implementation of
`nabto_device_threads.h` and a `nabto_device_platform.h`.

## `src/api/nabto_device_threads.h`

This file describes the thread interface used by the `nabto_device.h`
API.

There are currently two implementations of this interface, a pthread
and a win32 implementation. These implementation can be found in
`src/modules/threads/unix/nabto_device_threads_unix.c` and
`src/modules/threads/windows/nabto_device_threads_win.c`. These implementations
can be used for inspiration for a custom thread implementation for an
embedded target.

## `src/api/nabto_device_platform.h`

This file describes the functions needed by the `nabto_device.h` API
for initializing, deinitializing and stopping a platform.

Currently there is two implementations of the nabto device platform. A
libevent based and a unix select based implementation.

Libevent nabto device platform adapter, this is the default highlevel
implementation for linux, mac and windows this implementation is found
in the folder `src/nabto_device_libevent`

Unix Select based nabto device platform adapter, this adapter is used
as an example for how to implement the nabto device platform adapter
on an embedded target which has the select semantics. On other embedded
targets which do not come with select, the implementation still gives
a rough guidance for how the platform can be implemented. This
implementation is found in the folder `platform_integration_example`.
