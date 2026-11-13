### Added
 * `nabto_device_limit_coap_server_request_size()` limits the size of a CoAP
   request body, also when it is sent in multiple blocks. A larger request is
   rejected with 4.13 before it reaches the application. Before, a client could
   make the device reassemble a request body of any size.
 * The default resource limits can be set at build time through the platform
   config file (`NP_CONFIG_FILE`), see `src/core/nc_config.h`.

### Changed
 * The documentation of the `nabto_device_limit_*` functions now states that
   the limits are unlimited by default and that a device reachable by
   untrusted clients should set them. The defaults are unchanged.
