#ifndef NM_SELECT_UNIX_H
#define NM_SELECT_UNIX_H

#include <nabto_types.h>
#include <platform/np_udp.h>
#include <platform/np_platform.h>

/** defined here for testing purposes **/
void nm_select_unix_async_create(np_udp_socket_created_callback cb, void* data);
void nm_select_unix_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data);
void nm_select_unix_async_send_to(struct np_udp_send_context* ctx);
void nm_select_unix_async_recv_from(np_udp_socket* socket,
                                    np_udp_packet_received_callback cb, void* data);
void nm_select_unix_cancel_recv_from(np_udp_socket* socket);
void nm_select_unix_cancel_send_to(struct np_udp_send_context* socket);
enum np_ip_address_type nm_select_unix_get_protocol(np_udp_socket* socket);
uint16_t nm_select_unix_get_local_port(np_udp_socket* socket);
void nm_select_unix_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data);
int nm_select_unix_inf_wait(void);
int nm_select_unix_timed_wait(uint32_t ms);
void nm_select_unix_read(int nfds);


#endif // NM_SELECT_UNIX_H
