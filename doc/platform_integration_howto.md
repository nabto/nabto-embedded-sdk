
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
2. Timestamp - tools so that Nabto Edge knows about time for scheduling events
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


### `api/nabto_device.h`
This file contains 3 functions: an init, a deinit and a stop
function. That is, functions needed for bootstrap and teardown of the system.
These functions are called when a device is created,
destroyed and stopped. The init function should call the appropriate setterfunctions to setup the integration modules for the platform.

### `api/nabto_device_integration.h`

The purpose of these functions is to be called from the `nabto_device_platform_init` function to setup the module struct of
`src/platform/interfaces/*.h` (described later) via apropriate setter functions and to
provide the overall functionality which is required to run on a specific platform.


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

