
#include <platform/np_platform.h>

#define ATTACH_DISPATCHER_PORT 4433

typedef void (*nc_attached_callback)(const np_error_code ec, void* data);

np_error_code async_attach(struct np_platform* pl, nc_attached_callback cb, void* data);

