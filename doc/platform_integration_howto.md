
# Platform Integration Howto

This document is a short guide on how to create and integration to a
new platform for Nabto Edge.

## Overall architecture

<p align="center">
<img border="1" src="images/platform_integration_overview.svg">
</p>

Nabto Edge needs to know about the underlying platform it is running on.
The way to "inform" Nabto Edge about this platform is to implement a list
of functions and supply Nabto Edge with these functions. The list consists of
a list of functions defined in .h files and function pointers that are supplied to 
Nabto Edge via setup of structs.
Details on these structs can be found in **src/platform/interface/**
Nabto needs to know about: 

1. DNS - how to resolve hostnames to ip addresses (both ipv4:A and ipv6:AAAA addresses)
2. Timestamp - what is the time
3. Event Queue - put events on a queue for serialized (under mutex) execution, which minimizes/optimizes callstacks.
4. TCP - specify tcp operations
5. UDP - specify udp operations
6. Local ip - specify how to lookup the local-ip address(es) of the device
7. MDNS - specify MDNS interface for local discovery




## Components which is needed for a custom platform.

First of all, the Nabto Edge implementation files need to be included in the
development tool/ide of the new platform.

The specific needed list of files can be seen in nabto_files.cmake which also could be
used for IDEs capable of using cmake.

Once this is done, the Nabt Edge system needs to be supplied with knowledge of the platform/hardware it is running on.
3 major files need to be examined for this.


### `api/nabto_device_platform.h`

This file contains 3 functions: an init, a deinit and a stop
function. That is, functions needed for bootstrap and teardown of the system.
These functions are called when a device is created,
destroyed and stopped. 

The purpose of these functions is to setup the
`platform/np_platform.h` (described later) structs and to provide the overall functionality which
is required to run such a platform. The actual initialization of the platform happens from the
`nabto_device_init_platform` function. See `doc/np_platform.md` and the header file for further
information.

### `platform/np_platform.h`

The `platform/np_platform.h` contains specification of all the platform specific implementations.
These implentations consist of functions that are used by the core functionality inside Nabto Edge.
The .h files consist of several independent modules encapsulated in structs.
Each struct consists of a list of function pointers that needs to be setup in the bootstrap process (i.e the `nabto_device_init_platform` function).

Each module in `np_platform.h` should be implemented or an implementation which
is working on the desired platform should be choosen. 

### `api/nabto_device_threads.h`

The api `nabto/nabto_device.h` is a thread safe API, which also
exposes functionality which can block the system. The system currently 
also need to have a thread implementation. The thread
abstraction defines threads, muteces and condition variables. See
the header file for more information or take a look at the existing
implementations in the `src/modules/threads` folder.

## Example integration

In the directory `platform_integration_example` an example integration can be viewed. This example works on UNIX systems so
modules which works on such a system has been choosen. 

