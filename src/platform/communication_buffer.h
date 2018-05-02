#ifndef NABTO_COMMUNICATION_BUFFER_H
#define NABTO_COMMUNICATION_BUFFER_H

#include <types/linux/nabto_types.h> // HOW TO GENERALLY GET UINT8_T ????

typedef struct nabto_communication_buffer nabto_communication_buffer;

struct nabto_communication_buffer_module {
    nabto_communication_buffer* (*allocate)();
    void (*free)(nabto_communication_buffer*);
    uint8_t* (*start)(nabto_communication_buffer*);
    uint16_t (*size)(nabto_communication_buffer*);
};

#endif
