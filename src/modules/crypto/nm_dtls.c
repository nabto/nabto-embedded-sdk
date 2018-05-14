#include "nm_dtls.h"

void nm_dtls_init(struct np_platform* pl)
{
    pl->cryp.async_connect = &nm_dtls_async_connect;
    pl->cryp.async_send_to = &nm_dtls_async_send_to;
    pl->cryp.async_recv_from = &nm_dtls_async_recv_from;
    pl->cryp.async_close = &nm_dtls_async_close;
}

np_error_code nm_dtls_async_connect(struct np_platform* pl, np_crypto_context* ctx, struct np_connection* conn, np_crypto_connect_callback cb, void* data)
{
    return NABTO_EC_OK;
}

np_error_code nm_dtls_async_send_to(struct np_platform* pl, np_crypto_context* ctx, uint8_t* buffer, uint16_t bufferSize, np_crypto_send_to_callback cb, void* data)
{

    return NABTO_EC_OK;
}

np_error_code nm_dtls_async_recv_from(struct np_platform* pl, np_crypto_context* ctx, np_crypto_received_callback cb, void* data)
{

    return NABTO_EC_OK;
}

np_error_code nm_dtls_async_close(struct np_platform* pl, np_crypto_context* ctx, np_crypto_close_callback cb, void* data)
{

    return NABTO_EC_OK;
}
