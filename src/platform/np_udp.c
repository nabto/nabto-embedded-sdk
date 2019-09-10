#include "np_udp.h"


void np_udp_populate_send_context(struct np_udp_send_context* ctx, np_udp_socket* sock,
                                  struct np_udp_endpoint ep,
                                  uint8_t* buffer, uint16_t bufferSize,
                                  np_udp_packet_sent_callback cb, void* data)
{
    ctx->sock = sock;
    ctx->ep = ep;
    ctx->buffer = buffer;
    ctx->bufferSize = bufferSize;
    ctx->cb = cb;
    ctx->cbData = data;
}
