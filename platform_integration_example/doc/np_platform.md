# Low Level Platform Adapter

The low level platform adapters is the adapters defined in
`src/platform/np_platform.h` and related files. These files describes
interfaces for the following functionality:

 * UDP communication.
 * TCP communication.
 * DNS resolution.
 * Timestamps.
 * Event queue handling.
 * Dtls server and client handling.
 * Random generation.
 * MDNS server.

## Structure of the low level platform adapter

The low level platform adapter is a struct with lots of function
pointers and data pointers defined in `src/platform`.

E.g. the timestamp module consists of a single function. An
implementation of that module could look like

```
uint32_t timestamp_now_ms(struct np_platform* pl)
{
    struct custom_time_module* module = pl->tsData;
    uint32_t nowMs = ...
    return nowMs;
}

void custom_timestamp_init(struct np_platform* pl, struct custom_time_module* module)
{
    pl->tsData = module;
    pl->ts.now_ms = &timestamp_now_ms;
}
```

'custom_timestamp_init' should be called from 'nabto_device_init_platform' function called by the system when performing the bootstrap of the system.


The low level platform `src/platform/np_platform.h` can then be
implemented by using different modules. Either modules which already
exists or modules which is tailored for the specific platform. The
initialization of the complete set of modules often happens alsewhere.
