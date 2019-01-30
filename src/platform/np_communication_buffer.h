#ifndef NP_COMMUNICATION_BUFFER_H
#define NP_COMMUNICATION_BUFFER_H

#include <nabto_types.h>

typedef struct np_communication_buffer np_communication_buffer;

struct np_communication_buffer_module {
    np_communication_buffer* (*allocate)(void);
    void (*free)(np_communication_buffer*);
    uint8_t* (*start)(np_communication_buffer*);
    uint16_t (*size)(np_communication_buffer*);
};

#endif
