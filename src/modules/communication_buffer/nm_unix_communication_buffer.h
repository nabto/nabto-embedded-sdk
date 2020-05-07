#ifndef _NM_UNIX_COMMUNICATION_BUFFER_H_
#define _NM_UNIX_COMMUNICATION_BUFFER_H_

#include <platform/np_communication_buffer.h>
#include <platform/np_platform.h>
#include <types/linux/nabto_types.h>

#ifndef NABTO_COMMUNICATION_BUFFER_LENGTH
#define NABTO_COMMUNICATION_BUFFER_LENGTH 1500
#endif

//void nm_unix_comm_buf_init(struct np_platform* pl);

struct np_communication_buffer* nm_unix_comm_buf_allocate(void);

void nm_unix_comm_buf_free(struct np_communication_buffer* buf);

uint8_t* nm_unix_comm_buf_start(struct np_communication_buffer* buf);

uint16_t nm_unix_comm_buf_size(struct np_communication_buffer* buf);

#endif // _NM_UNIX_COMMUNICATION_BUFFER_H_
