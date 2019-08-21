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

struct np_platform {
    // Timestamp module
    struct np_timestamp_module ts;

    // Event Queue module
    struct np_event_queue eq;

    // UDP Socket module
    struct np_udp_module udp;
    // Data for the udp module object
    void* udpData;

    // Communication buffer module
    struct np_communication_buffer_module buf;

    // DNS resolver module
    struct np_dns_module dns;

    // DTLS client module
    struct np_dtls_cli_module dtlsC;

    // DTLS server module
    struct np_dtls_srv_module dtlsS;

    // Tcp socket module
    struct np_tcp_module tcp;
    // Data pointer set when tcp module is initialized.
    void* tcpData;
};

/**
 * Initialize the platform structure.
 */
void np_platform_init(struct np_platform* pl);

#endif
