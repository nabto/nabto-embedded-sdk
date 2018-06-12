#ifndef NC_ATTACHER_H
#define NC_ATTACHER_H

#include <platform/np_platform.h>

#define ATTACH_DISPATCHER_PORT 4433

typedef void (*nc_attached_callback)(const np_error_code ec, void* data);

// This should possibly use nc_attached_state instead of np_error_code
typedef void (*nc_detached_callback)(const np_error_code ec, void* data);

np_error_code nc_attacher_async_attach(struct np_platform* pl, nc_attached_callback cb, void* data);

np_error_code nc_attacher_register_detatch_callback(nc_detached_callback cb, void* data);

#endif //NC_ATTACHER_H
