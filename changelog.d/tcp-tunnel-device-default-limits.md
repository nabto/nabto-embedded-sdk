### Changed
 * The `tcp_tunnel_device` app is now limited by default. It accepts 100
   connections, 500 streams, 262144 stream segments (64MB), 200 concurrent
   CoAP requests, CoAP request bodies of 64KB and 200 TCP connections per
   tunnel service type. Before, all were unlimited. The limits can be changed
   with the `--limit-*` options and removed with a negative value, e.g.
   `--limit-streams=-1`.

### Added
 * `tcp_tunnel_device` options `--limit-coap-requests`,
   `--limit-coap-request-size` and `--limit-tunnel-connections`.
