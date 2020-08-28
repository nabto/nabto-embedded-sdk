#ifndef NP_MDNS_H
#define NP_MDNS_H

#include <stdint.h>
#include <platform/np_error_code.h>

/**
 * @intro mDNS interface
 *
 * The Device has the possibility to expose its nabto service via
 * mDNS.
 *
 * mDNS quick guide:
 *
 * mDNS stands for multicast DNS. Multicast DNS is implemented by an
 * mDNS server and an mDNS client. The mDNS server joins a multicast
 * group on port 5353 where it listens for DNS packets. When the mDNS
 * server receives a packet, it creates a response packet for that
 * request.
 *
 * mDNS uses a concept called service types. A service type is
 * e.g. `_nabto._udp`. The service type is concatenated with a domain,
 * e.g. `.local` to create a domain name. This means that the service
 * exposed by a mDNS server for the nabto service is
 * `_nabto._udp.local`.
 *
 * An mDNS server then listens for PTR queries. When a PTR request for
 * `_nabto._udp.local` is received the mDNS server answers the request
 * with the name of the nabto service on the device
 * e.g. `<device-id>._nabto._udp.local`.
 *
 * SRV and TXT lookups are then made to the specific service
 * name. E.g. `<device-id>._nabto._udp.local`. This lookup answers with
 * TXT records and an SRV record. The SRV record contains the actual
 * hostname of the device and the port number of the service. The
 * hostname can then be resolved to A and AAAA records. The TXT
 * records contain additional data for the service on this specific
 * device e.g. productid and deviceid.
 *
 * Implementations of this module should expose an mDNS service with
 * the following items:
 *
 * Service type: `_nabto._udp`
 * Txt records: `productid=<productid>, deviceid=<deviceid>`
 * Port number: `<the udp port number of the nabto service>`
 * Sub type: `<productid>-<deviceid>._sub._nabto._udp.local.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct np_mdns_functions;
struct nn_string_set;
struct nn_string_map;

struct np_mdns {
    const struct np_mdns_functions* mptr;
    void* data;
};

struct np_mdns_functions {
    /**
     * Publish the mDNS service for the device.
     *
     * @param obj  The mDNS server implementation.
     * @param port  The UDP port number to expose for the service.
     * @param instanceName  The instance portion of the service name
     * @param subtypes  subtypes to expose
     * @param txtItems  txt items to expose
     */
    void (*publish_service)(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_MDNS_H
