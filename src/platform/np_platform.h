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
#include <platform/np_crypto.h>
#include <platform/np_connection.h>
#include <platform/np_client_connect.h>

struct np_platform {
    // Timestamp module
    struct np_timestamp_module ts;

    // Event Queue module
    struct np_event_queue eq;

    // UDP Socket module
    struct np_udp_module udp;

    // Communication buffer module
    struct np_communication_buffer_module buf;

    // DNS resolver module
    struct np_dns_module dns;

    // Crypto module
    struct np_crypto_module cryp;

    // connection module
    struct np_connection_module conn;

    // client connect module
    struct np_client_connect_module clientConn;
};

/**
 * Initialize the platform structure.
 */
void np_platform_init(struct np_platform* pl);

#endif
