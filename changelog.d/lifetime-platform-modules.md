### Added
 * `nm_unix_dns_resolver_stop()` for platform integrations which use the unix
   DNS resolver. It resolves outstanding requests with `NABTO_EC_STOPPED` and
   should be called from `nabto_device_platform_stop_blocking()`. The
   select_unix platform integration example does this.

### Bug fixes
 * The libevent TCP module resolved the wrong completion event when
   `np_tcp_async_read` was called while a read was already pending. The
   pending read was completed with `NABTO_EC_OPERATION_IN_PROGRESS`, and later
   completed a second time, while the new read was never completed. Now the new
   read fails with `NABTO_EC_OPERATION_IN_PROGRESS` and the pending read is left
   alone, as in the select_unix module. `np_tcp_async_connect` on a socket
   which is already connecting is rejected the same way, instead of replacing
   the pending connect. Operations started on an aborted socket fail with
   `NABTO_EC_ABORTED`.
 * The select_unix TCP and UDP modules could complete an operation twice when
   a socket was aborted while the network thread completed the same
   operation.
 * The unix DNS resolver could complete a request after the device was
   stopped, and wrote the result into memory the device had already freed.
   It now copies the host name and only writes the result if the request is
   still outstanding.
 * Freeing a TCP probe with an outstanding reachability check used freed
   memory. The check is now aborted and its future resolved.
 * A CoAP packet which could not be handed to the DTLS connection, e.g.
   because the connection was closing, stalled the CoAP server or client for
   all connections. Such a packet is now dropped. A stream RST which could
   not be sent blocked all later RSTs in the same way.
