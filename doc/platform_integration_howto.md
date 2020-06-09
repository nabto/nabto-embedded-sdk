
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

1. DNS - how the system resolves hostnames to ip addresses (both ipv4:A and ipv6:AAAA addresses)
2. Timestamp - interface for Nabto Edge to know about the current time for scheduling events
3. Event Queue - put events on a queue for serialized (under mutex) execution, which minimizes/optimizes callstacks.
4. TCP - specify TCP operations on the specific target
5. UDP - specify UDP operations on the specific target
6. Local ip - specify how to find the local-ip address(es) of the device (ie. which IP does the target have on the local network)
7. MDNS - specify/setup MDNS interface for local discovery


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
destroyed and stopped. The init function should call the appropriate setterfunctions to setup the integration modules for the platform.

### `api/nabto_device_integration.h`

The purpose of these functions is to be called from the `nabto_device_platform_init` function to setup the module struct of
`src/platform/interfaces/*.h` (described later) via apropriate setter functions and to
provide the overall functionality which is required to run on a specific platform.

### Understanding nabto_device_platform.h and nabto_device_device_integration.h setup in an integration

For better understanding the link between the initialisation of a device and the platform integration please refer to the next diagram.

<p align="center">
<img border="1" src="images/nabto_device_platform_cdiag.svg">
</p>

The call sequence and initialization of the integration modules will start when the main program initializes a new NabtoDevice, something like:

```
NabtoDevice* device = nabto_device_new();
```

This will at some point call the initialization of the integration interface (`nabto_devcie_platform_init`) which has the responsibillity to setup the different integration modules (tcp, udp, mdns, timestamp etc.) via calling the appropriate nabto_device_interation_set_<modulename>_impl().
    


#### Platform specific data utillity functions `nabto_device_integration_set_platform_data` and `nabto_device_integration_get_platform_data`

When setting up the integration modules, the integrator will probably allocate different types of resources. These resources will need to be deallocated later on when/if the Nabto platform is stopped.

This can be accomplished by setting a pointer to the user specified data via the `nabto_device_integration_set_platform_data` and `nabto_device_integration_get_platform_data` function which is reachable inside both the the `nabto_device_platform_init`, `nabto_device_platform_init` and `nabto_devcie_platform_stop` function. This way a pointer to the data can be created and stored in init and deallocated in deinit and stop.

If the integration is sure that only on instance of the nabto device is started on a specific device (via `nabto_device_new()`) this user specified data could reside in a static single allocated location (and there will be no need for either the `nabto_device_integration_set_platform_data` or `nabto_device_integration_get_platform_data`) but for the general case multiple devices could run inside the same environment and memory, so the functions are supplied.


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

## Example of a simple module - struct np_timestamp_functions

This is one of the most simple integration interfaces, so it is a good place to start. 
This interface tells Nabto Edge how to get the current time from the system. This is used to keep track of retransmissions of internet communication etc. The interface can be found in `nabto-embedded-sdk/src/platform/interfaces/np_timestamp.h` and looks like this:

```
struct np_timestamp_functions {
    /**
     * Return current timestamp as milliseconds the timestamp should
     * be a monotonic value which wraps around whenever the value
     * reaches 2^32. The precision is not critical.
     *
     * @param  data  The timestamp object data.
     * @return  The current timestamp in milliseconds.
     */
    uint32_t (*now_ms)(struct np_timestamp* obj);
}

struct np_timestamp {
    const struct np_timestamp_functions* vptr;
    // Pointer to data which is implementation specific
    void* data;
};

```
The np_timestamp struct defines the modules data (`void* data`) and the functions (`struct np_timestamp_functions* vptr`). The data section is a pointer that is fully up to the implementation integration to use and implement or not use at all.

The `np_timestampe_functions` defines a set of functions that the integration modules supply. For the timestamp module this is very simple since it is only one function `uint32_t ts_now_ms(struct np_timestamp* obj)`

On Linux this interface could be accomplished by making the following function (please refer to the `clock_gettime` function):

```
uint32_t ts_now_ms(struct np_timestamp* obj)
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return ((spec.tv_sec * 1000) + (spec.tv_nsec / 1000000));
}
```

To create the np_timestamp_functions table you could do the following:

```
static struct np_timestamp_functions vtable = {
    .now_ms               = &ts_now_ms
};
```

And to make a function that setup the np_timestamp struct is would look like:

```
struct np_timestamp nm_unix_ts_create()
{
    struct np_timestamp ts;
    ts.vptr = &vtable;
    ts.data = NULL;
    return ts;
}
```
(note this implementation of np_timestamp does not use the user supplied data for anything since there's no need for it specific implmentation.)

To setup the timestamp integration modules the intergrator could now do something like:

```
np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* eventMutex) {

    ...
    
    struct np_timestamp timestampImpl = nm_unix_ts_create();
    nabto_device_integration_set_timestamp_impl(device, &timestampImpl);

    ...
    
}
```

Not that the `nabto_device_integration_set_timestamp_impl` functions all copies the implementation structs even though they are pointers (to be sure that users does not make a mistake of .


# Integration procedure

Of course an integration procedure can be that all module functions are correctly implement from start to end and in the end everything is joined and everything works (big-bang integration). This mostly is a very very hard way to do an integration since it is wellknown that it is nearly impossible to write so much code without an error is sneaked in and this error will can be very very hard to located in a running system.

Instead in Nabto Edge a integration procedure is laid out with supporting test code so that the integrator can create the integration interfaces one by one and get them tested. Thus once the overall integration is to be made, hopefully no errors (or only minor errors) will occur.

The integration procedure with supporting tests are as follows:

1. Log interface
2. Timestamp interface
3. Threads interface
4. Event queue
5. DNS interface
6. UDP interface
7. TCP interface
8. LocalIP interface
9. MDNS


