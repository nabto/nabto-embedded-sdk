#ifndef NP_PLATFORM_H
#define NP_PLATFORM_H
/**
 * The platform is the main entry point, it includes references and
 * data for all relevant platform functions which can be called from
 * the core.
 */

#include <platform/np_timestamp.h>
#include <platform/np_event_queue.h>
#include <platform/np_udp.h>
#include <platform/np_communication_buffer.h>
#include <platform/np_dns.h>
#include <platform/np_dtls_cli.h>
#include <platform/np_dtls_srv.h>
#include <platform/np_tcp.h>
#include <platform/np_mdns.h>
#include <platform/np_authorization.h>
#include <platform/np_random.h>
#include <platform/np_local_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform {
    // Data pointer to custom data used for implementing the platform functionality
    void* platformData;

    // Timestamp module
    struct np_timestamp_functions ts;
    struct np_timestamp_object* tsImpl;

    // Event Queue module
    struct np_event_queue_functions eq;
    void* eqData;  // Custom data for the event queue module

    // UDP Socket module
    struct np_udp_functions udp;
    struct np_udp_object* udpImpl;  // Custom data for the udp module object

    // DNS resolver module
    struct np_dns_functions dns;
    struct np_dns_object* dnsData;  // Custom data for the dns module.

    // Tcp socket module
    struct np_tcp_functions tcp;
    struct np_tcp_object* tcpData;  // Custom data for the TCP module.

    // Random module
    struct np_random_module random;
    void* randomData; // Custom data for the random module.

    // Local ip module.
    struct np_local_ip localIp;
    void* localIpData;  // Custom data for the local ip module.


    // The following modules are not final yet and they are subject to
    // changes in the future.

    // Communication buffer module
    struct np_communication_buffer_module buf;

    // DTLS client module
    struct np_dtls_cli_module dtlsC;
    void* dtlsCData; // Custom data for the dtls client module.

    // DTLS server module
    struct np_dtls_srv_module dtlsS;
    void* dtlsSData; // Custom data for the dtls server module.

    // Mdns module
    struct np_mdns_module mdns;
    void* mdnsData;  // Custom data for the mdns module.

    // Access control module
    struct np_authorization authorization;
    void* authorizationData;

};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
