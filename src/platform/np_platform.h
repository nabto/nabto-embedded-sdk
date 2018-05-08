#ifndef NP_PLATFORM_H
#define NP_PLATFORM_H
/**
 * The platform is the main entry point, it includes references and
 * data for all relevant platform functions which can be called from
 * the core.
 */

#include <platform/np_timestamp.h>
#include <platform/np_udp.h>
#include <platform/np_event_queue.h>
#include <platform/np_communication_buffer.h>
#include <platform/np_dns.h>

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
};

/**
 * Initialize the platform structure.
 */
void np_platform_init(struct np_platform* pl);

#endif
