#include "nm_communication_buffer.h"

#include <platform/np_allocator.h>
#include <platform/np_communication_buffer.h>
#include <platform/np_logging.h>
#include <platform/np_platform.h>



#define LOG NABTO_LOG_MODULE_CORE


static struct np_communication_buffer* buf_allocate(void);

static void buf_free(struct np_communication_buffer* buf);

static uint8_t* buf_start(struct np_communication_buffer* buf);

static uint16_t buf_size(struct np_communication_buffer* buf);


struct np_communication_buffer {
    uint8_t* buf;
    uint16_t size;
};


void nm_communication_buffer_init(struct np_platform* pl)
{
    pl->buf.allocate = &buf_allocate;
    pl->buf.free     = &buf_free;
    pl->buf.start    = &buf_start;
    pl->buf.size     = &buf_size;
}

struct np_communication_buffer* buf_allocate()
{
    struct np_communication_buffer* buf = (struct np_communication_buffer*)np_calloc(1, sizeof(struct np_communication_buffer));
    if (!buf) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate communication buffer structure");
        return NULL;
    }
    buf->buf = (uint8_t*)np_calloc(1, NABTO_COMMUNICATION_BUFFER_LENGTH);
    if (!buf->buf) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate communication buffer");
        np_free(buf);
        return NULL;
    }
    buf->size = NABTO_COMMUNICATION_BUFFER_LENGTH;
    return buf;
}

void buf_free(struct np_communication_buffer* buf)
{
    if (buf == NULL) {
        return;
    }
    np_free(buf->buf);
    np_free(buf);
}

uint8_t* buf_start(struct np_communication_buffer* buf)
{
    return buf->buf;
}

uint16_t buf_size(struct np_communication_buffer* buf)
{
    return buf->size;
}
