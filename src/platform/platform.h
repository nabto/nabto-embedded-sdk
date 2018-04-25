#ifndef NABTO_PLATFORM_H
#define NABTO_PLATFORM_H
/**
 * The platform is the main entry point, it includes references and
 * data for all relevant platform functions which can be called from
 * the core.
 */

#include <platform/timestamp.h>
#include <platform/udp.h>
#include <platform/event_queue.h>


struct nabto_platform {
    // Timestamp module
    struct nabto_timestamp_module ts;

    // Event Queue module
    struct nabto_event_queue eq;

    // UDP Socket Module
    struct nabto_udp_module udp;
};

/**
 * Initialize the platform structure.
 */
void nabto_platform_init(struct nabto_platform* pl);

#endif
