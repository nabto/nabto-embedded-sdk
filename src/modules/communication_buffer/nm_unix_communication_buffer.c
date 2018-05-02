#include "nm_unix_communication_buffer.h"
#include <stdlib.h>


struct nabto_communication_buffer {
    uint8_t* buf;
    uint16_t size;
};


void nm_unix_comm_buf_init(struct nabto_platform* pl)
{
    pl->buf.allocate = &nm_unix_comm_buf_allocate;
    pl->buf.free     = &nm_unix_comm_buf_free;
    pl->buf.start    = &nm_unix_comm_buf_start;
    pl->buf.size     = &nm_unix_comm_buf_size;
}

nabto_communication_buffer* nm_unix_comm_buf_allocate()
{
    nabto_communication_buffer* buf = (nabto_communication_buffer*)malloc(sizeof(nabto_communication_buffer));
    buf->buf = (uint8_t*)malloc(NABTO_COMMUNICATION_BUFFER_LENGTH);
    buf->size = NABTO_COMMUNICATION_BUFFER_LENGTH;
    return buf;
}

void nm_unix_comm_buf_free(nabto_communication_buffer* buf)
{
    free(buf->buf);
    free(buf);
}

uint8_t* nm_unix_comm_buf_start(nabto_communication_buffer* buf)
{
    return buf->buf;
}

uint16_t nm_unix_comm_buf_size(nabto_communication_buffer* buf)
{
    return buf->size;
}
