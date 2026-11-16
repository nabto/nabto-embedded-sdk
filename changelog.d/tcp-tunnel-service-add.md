### Bug fixes
 * `nabto_device_add_tcp_tunnel_service` freed nothing when adding the
   service failed, leaking the service. It now also returns
   `NABTO_DEVICE_EC_IN_USE` for a service id which is already in use.
   Previously the second service was added but could never be reached, as
   lookups by id found the first one. The TCP tunnel device app therefore
   stops at startup if its services file has two services with the same id.
