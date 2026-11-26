### Bug fixes
 * On a platform without a TCP module, `nabto_device_add_tcp_tunnel_service()`,
   `nabto_device_remove_tcp_tunnel_service()`,
   `nabto_device_add_tcp_tunnel_service_metadata()`,
   `nabto_device_remove_tcp_tunnel_service_metadata()` and
   `nabto_device_limit_tcp_tunnel_connections()` now return
   `NABTO_DEVICE_EC_NOT_IMPLEMENTED`. They used to dereference the TCP tunnel
   state, which is not initialized without a TCP module.
