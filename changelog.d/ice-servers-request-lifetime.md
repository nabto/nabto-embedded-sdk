### Security
 * Fixed a crash in `nabto_device_stop()` when an ICE servers request had been
   created with `nabto_device_ice_servers_request_new()` but not sent. The same
   crash happened when the basestation connection was reset before the request
   was sent. A request sent after the device had reattached used the old,
   freed basestation connection.
 * `nabto_device_ice_servers_request_new()` no longer touches the device
   without holding its lock.
 * `nabto_device_ice_servers_request_free()` now resolves the future of a
   request which is still in progress with `NABTO_DEVICE_EC_STOPPED`.
   Previously the future was never resolved.
