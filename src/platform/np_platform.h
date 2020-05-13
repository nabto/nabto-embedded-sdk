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

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform {
    // Data pointer to custom data used for implementing the platform functionality
    void* platformData;

    // Timestamp module
    struct np_timestamp_module ts;
    // data for the timestamp module
    void* tsData;

    // Event Queue module
    struct np_event_queue eq;
    // Data for the event queue module
    void* eqData;

    // UDP Socket module
    struct np_udp_module udp;
    // Data for the udp module object
    void* udpData;

    // DNS resolver module
    struct np_dns_module dns;
    void* dnsData;

    // Tcp socket module
    struct np_tcp_module tcp;
    // Data pointer set when tcp module is initialized.
    void* tcpData;

    // Random source
    struct np_random_module random;
    void* randomData; // userdata for the random module.


    // Communication buffer module
    struct np_communication_buffer_module buf;

    // DTLS client module
    struct np_dtls_cli_module dtlsC;

    // DTLS server module
    struct np_dtls_srv_module dtlsS;

    // Mdns
    struct np_mdns_module mdns;
    // mdns module data
    void* mdnsData;

    // Access control module
    struct np_authorization authorization;
    void* authorizationData;
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
