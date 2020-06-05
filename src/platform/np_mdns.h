#ifndef NP_MDNS_H
#define NP_MDNS_H

#include <stdint.h>
#include <platform/np_error_code.h>

/**
 * MDNS interface.
 *
 * The Device has the possibility to expose its nabto service via
 * MDNS.
 *
 * The service type which should be registered is
 * `_nabto._udp`.
 *
 * MDNS quick guide:
 *
 * MDNS stands for multicast DNS. Multicast dns is implemented by a
 * MDNS server and a MDNS client. The MDNS server joins a multicast
 * group on port 5353 where it listens for DNS packets. When the MDNS
 * server receives a packet it creates a response packet for that
 * request.
 *
 * MDNS uses a concept called service types. A service types is
 * e.g. _nabto._udp. The service type is concatinated with a domain,
 * e.g. .local. This means that the service exposed by a MDNS server for
 * the nabto service is _nabto._udp.local.
 *
 * A mdns server then listens for PTR queries. When a PTR request for
 * _nabto._udp.local is received the mdns server answer back with the
 * dns name of the nabto service. The dns name is a specific name for
 * the actual service and not a generic name.
 *
 * SRV and TXT lookups is then made to the instance specific service
 * name. E.g. <device-id>._nabto._udp.local. This lookup then answers
 * with TXT records and SRV records. The SRV record contains the
 * actual hostname of the device and the port number of the
 * service. The hostname can then be resolved to A and AAAA
 * records. The TXT records contains additional data for the service
 * on this specific address. These records could be the version,
 * device id, product id or other simple but relevant information.
 *
 * Implementations of this module should expose a mdns service with
 * the following items:
 *
 * Service type: _nabto._udp.
 * Txt records: productid=<productid>, deviceid=<deviceid>
 * Port number: <the udp port number of the nabto service>
 */

#ifdef __cplusplus
extern "C" {
#endif

struct np_mdns_functions;

struct np_mdns {
    const struct np_mdns_functions* vptr;
    void* data;
};

struct np_mdns_functions {
    /**
     * Publihs the mdns service for the device.
     *
     * @param obj  The mdns server implementation.
     * @param port  The port number to expose for the service.
     * @param productId  The productId to expose in a TXT record.
     * @param deviceId The device id to expose in a TXT record.
     */
    void (*publish_service)(struct np_mdns* obj, uint16_t port, const char* productId, const char* deviceId);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_MDNS_H
