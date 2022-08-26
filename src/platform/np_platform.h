#ifndef NP_PLATFORM_H
#define NP_PLATFORM_H
/**
 * The platform is the main entry point, it includes references and
 * data for all relevant platform functions which can be called from
 * the core.
 */

#include <nabto/nabto_device_config.h>
#include <platform/interfaces/np_timestamp.h>
#include <platform/interfaces/np_event_queue.h>
#include <platform/interfaces/np_udp.h>
#include <platform/np_communication_buffer.h>
#include <platform/interfaces/np_dns.h>
#include <platform/np_dtls_cli.h>
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
#include <platform/np_dtls_srv.h>
#endif
#include <platform/interfaces/np_tcp.h>
#include <platform/interfaces/np_mdns.h>
#include <platform/np_authorization.h>
#include <platform/np_random.h>
#include <platform/np_spake2.h>
#include <platform/interfaces/np_local_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform {
    // Data pointer to custom data used for implementing the platform functionality
    void* platformData;

    // Timestamp module
    struct np_timestamp timestamp;

    // Event Queue module
    struct np_event_queue eq;

    // UDP Socket module
    struct np_udp udp;

    // DNS resolver module
    struct np_dns dns;

    // Tcp socket module
    struct np_tcp tcp;

    // Local ip module.
    struct np_local_ip localIp;

    // Mdns module
    struct np_mdns mdns;


    // The following modules are not final yet and they are subject to
    // changes in the future.

    // Random module
    struct np_random_module random;
    void* randomData; // Custom data for the random module.

    // Communication buffer module
    struct np_communication_buffer_module buf;

    // DTLS client module
    struct np_dtls_cli_module dtlsC;
    void* dtlsCData; // Custom data for the dtls client module.

#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    // DTLS client module
    struct np_dtls_srv_module dtlsS;
    void* dtlsSData; // Custom data for the dtls client module.
#endif

    // Access control module
    struct np_authorization authorization;
    void* authorizationData;

    // spake2
    struct np_spake2_module spake2;
    void* spake2Data;
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
