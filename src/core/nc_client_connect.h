#ifndef NC_CLIENT_CONNECT_H
#define NC_CLIENT_CONNECT_H

#include <platform/np_platform.h>
#include <platform/np_client_connect.h>

np_error_code nc_client_connect_new(struct np_platform* pl, enum np_channel_type type, uint8_t* id,
                                       uint8_t idSize, struct np_udp_socket* sock, struct np_udp_endpoint* ep);
np_connection* nc_client_connect_get(struct np_platform* pl, uint8_t* id, uint8_t idSize);
np_error_code nc_client_connect_recv(const np_error_code ec, struct np_udp_endpoint ep,
                                     np_communication_buffer* buffer, uint16_t bufferSize);


#endif //_NC_CLIENT_CONNECT_H_
