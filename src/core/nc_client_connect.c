#include "nc_client_connect.h"
#include <platform/np_error_code.h>


np_error_code nc_client_connect_new(struct np_platform* pl, enum np_channel_type type, uint8_t* id,
                                       uint8_t idSize, struct np_udp_socket* sock, struct np_udp_endpoint* ep)
{
    return NABTO_EC_OK;
}

np_connection* nc_client_connect_get(struct np_platform* pl, uint8_t* id, uint8_t idSize)
{
    return NULL;
}

np_error_code nc_client_connect_recv(struct np_udp_socket* sock, struct np_udp_endpoint ep,
                                     np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    return NABTO_EC_OK;
}
