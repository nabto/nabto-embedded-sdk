#include "nm_unix_communication_buffer.h"

#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_CORE


struct np_communication_buffer {
    uint8_t* buf;
    uint16_t size;
};


void np_communication_buffer_init(struct np_platform* pl)
{
    pl->buf.allocate = &nm_unix_comm_buf_allocate;
    pl->buf.free     = &nm_unix_comm_buf_free;
    pl->buf.start    = &nm_unix_comm_buf_start;
    pl->buf.size     = &nm_unix_comm_buf_size;
}

np_communication_buffer* nm_unix_comm_buf_allocate()
{
    np_communication_buffer* buf = (np_communication_buffer*)malloc(sizeof(np_communication_buffer));
    if (!buf) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate communication buffer structure");
        return NULL;
    }
    buf->buf = (uint8_t*)malloc(NABTO_COMMUNICATION_BUFFER_LENGTH);
    if (!buf->buf) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate communication buffer");
        free(buf);
        return NULL;
    }
    buf->size = NABTO_COMMUNICATION_BUFFER_LENGTH;
    return buf;
}

void nm_unix_comm_buf_free(np_communication_buffer* buf)
{
    if (buf == NULL) {
        return;
    }
    free(buf->buf);
    free(buf);
}

uint8_t* nm_unix_comm_buf_start(np_communication_buffer* buf)
{
    return buf->buf;
}

uint16_t nm_unix_comm_buf_size(np_communication_buffer* buf)
{
    return buf->size;
}
