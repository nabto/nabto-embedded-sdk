#ifndef NP_COMMUNICATION_BUFFER_H
#define NP_COMMUNICATION_BUFFER_H

#include <platform/np_types.h>

/**
 * Communication buffer interface.
 *
 * Warning: This interface will maybe change in the future.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct np_communication_buffer;

struct np_platform;

struct np_communication_buffer_module {
    struct np_communication_buffer* (*allocate)(void);
    void (*free)(struct np_communication_buffer*);
    uint8_t* (*start)(struct np_communication_buffer*);
    uint16_t (*size)(struct np_communication_buffer*);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
