#include "np_tcp_wrapper.h"



np_error_code np_tcp_create(struct np_tcp* obj, struct np_tcp_socket** sock)
{
    return obj->mptr->create(obj, sock);
}
void np_tcp_destroy(struct np_tcp* obj, struct np_tcp_socket* sock)
{
    obj->mptr->destroy(sock);
}
void np_tcp_async_connect(struct np_tcp* obj, struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent)
{
    obj->mptr->async_connect(sock, address, port, completionEvent);
}
void np_tcp_async_write(struct np_tcp* obj, struct np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent)
{
    obj->mptr->async_write(sock, data, dataLength, completionEvent);
}
void np_tcp_async_read(struct np_tcp* obj, struct np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent)
{
    obj->mptr->async_read(sock, buffer, bufferLength, readLength, completionEvent);
}
void np_tcp_shutdown(struct np_tcp* obj, struct np_tcp_socket* sock)
{
    obj->mptr->shutdown(sock);
}
void np_tcp_abort(struct np_tcp* obj, struct np_tcp_socket* sock)
{
    obj->mptr->abort(sock);
}
