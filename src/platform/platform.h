#ifndef NABTO_PLATFORM_H
#define NABTO_PLATFORM_H



#include <platform/types.h>
#include <platform/error_code.h>
#include <platform/timestamp.h>
#include <platform/event_queue.h>

/**
 * The nabto platform is an object containing references to all the
 * different parts the system consists of.
 */


/**
 * The platform is the main entry point, it includes references and
 * data for all relevant platform functions which can be called from
 * the core.
 */
    
struct nabto_platform {
    // Timestamp module
    struct nabto_timestamp_module ts;

    // Event Queue module
    struct nabto_event_queue eq;
};

/**
 * Initialize the platform structure.
 */
void nabto_platform_init(struct nabto_platform* pl);

#endif
