#ifndef NM_DTLS_SRV_H
#define NM_DTLS_SRV_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>
#include <core/nc_client_connection.h>

np_error_code nm_dtls_srv_create(struct np_platform* pl, struct np_dtls_srv_connection** dtls,
                                 np_dtls_srv_sender sender,
                                 np_dtls_srv_data_handler dataHandler,
                                 np_dtls_srv_event_handler eventHandler,
                                 void* data);

np_error_code nm_dtls_srv_async_send_data(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                          struct np_dtls_srv_send_context* sendCtx);

np_error_code nm_dtls_srv_async_close(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                      np_dtls_close_callback cb, void* data);

np_error_code nm_dtls_srv_get_fingerprint(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                          uint8_t* fp);

#endif // NM_DTLS_SRV_H
