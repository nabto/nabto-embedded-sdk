#ifndef NP_DTLS_H
#define NP_DTLS_H



typedef void (*np_dtls_send_to_callback)(const np_error_code ec, void* data);

typedef void (*np_dtls_received_callback)(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                          struct np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_dtls_close_callback)(const np_error_code ec, void* data);

#endif // NP_DTLS_H
