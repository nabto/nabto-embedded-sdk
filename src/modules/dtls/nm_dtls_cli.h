#ifndef NM_DTLS_CLI_H
#define NM_DTLS_CLI_H

#include <platform/np_platform.h>
#include <platform/np_dtls_cli.h>

np_error_code nm_dtls_async_send_to(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t channelId,
                                    uint8_t* buffer, uint16_t bufferSize, np_dtls_send_to_callback cb, void* data);
np_error_code nm_dtls_async_recv_from(struct np_platform* pl, np_dtls_cli_context* ctx,
                                      enum application_data_type type, np_dtls_received_callback cb, void* data);
np_error_code nm_dtls_cancel_recv_from(struct np_platform* pl, np_dtls_cli_context* ctx,
                                       enum application_data_type type);
np_error_code nm_dtls_async_close(struct np_platform* pl, np_dtls_cli_context* ctx,
                                  np_dtls_close_callback cb, void* data);

np_error_code nm_dtls_get_fingerprint(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t* fp);

#endif // NM_DTLS_CLI_H
