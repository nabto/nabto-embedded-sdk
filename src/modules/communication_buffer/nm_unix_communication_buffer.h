#ifndef _NM_UNIX_COMMUNICATION_BUFFER_H_
#define _NM_UNIX_COMMUNICATION_BUFFER_H_

#include <platform/communication_buffer.h>
#include <platform/platform.h>
#include <types/linux/nabto_types.h>

#ifndef NABTO_COMMUNICATION_BUFFER_LENGTH
#define NABTO_COMMUNICATION_BUFFER_LENGTH 1500
#endif

void nm_unix_comm_buf_init(struct nabto_platform* pl);

nabto_communication_buffer* nm_unix_comm_buf_allocate();

void nm_unix_comm_buf_free(nabto_communication_buffer* buf);

uint8_t* nm_unix_comm_buf_start(nabto_communication_buffer* buf);

uint16_t nm_unix_comm_buf_size(nabto_communication_buffer* buf);

#endif // _NM_UNIX_COMMUNICATION_BUFFER_H_
