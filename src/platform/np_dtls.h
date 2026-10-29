#ifndef NP_DTLS_H
#define NP_DTLS_H
#include <nn/llist.h>
#include <platform/np_completion_event.h>

#define NP_DTLS_DEFAULT_CHANNEL_ID 0xff

/**
 * Upper bound on the number of bytes a DTLS record adds to the plaintext it
 * carries. With TLS_ECDHE_ECDSA_WITH_AES_128_CCM it is 37 bytes: a 13 byte
 * record header, an 8 byte explicit nonce and a 16 byte tag.
 *
 * Each record is sent from a communication buffer, so data given to
 * async_send_data must be at most the size of a communication buffer minus
 * this overhead. The DTLS modules refuse data which does not fit.
 */
#define NP_DTLS_MAX_RECORD_OVERHEAD 64

struct np_communication_buffer;

enum np_dtls_event {
    NP_DTLS_EVENT_CLOSED, // The connection is closed
    NP_DTLS_EVENT_HANDSHAKE_COMPLETE,
    NP_DTLS_EVENT_ACCESS_DENIED, // The connection got an access denied alert. The connection is closed.
    NP_DTLS_EVENT_CERTIFICATE_VERIFICATION_FAILED // The certificate could not be validated. The connection is closed.
};

typedef np_error_code (*np_dtls_sender)(uint8_t channelId, uint8_t* buffer,
                                        uint16_t bufferSize,
                                        struct np_completion_event* cb,
                                        void* senderData);
typedef void (*np_dtls_event_handler)(enum np_dtls_event event,
                                      void* data);
typedef void (*np_dtls_data_handler)(uint8_t channelId, uint64_t seq,
                                     uint8_t* buffer, uint16_t bufferSize,
                                     void* data);
struct np_dtls_send_context {
    // Data to send
    uint8_t* buffer;
    uint16_t bufferSize;
    // channel ID unused by DTLS, but passed to data_handler/sender as needed by nc_client_connection
    uint8_t channelId;
    // callback when sent
    struct np_completion_event ev;
    // node for message queue
    struct nn_llist_node sendListNode;
};



typedef void (*np_dtls_send_to_callback)(const np_error_code ec, void* data);

typedef void (*np_dtls_received_callback)(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                          struct np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_dtls_close_callback)(const np_error_code ec, void* data);

#endif // NP_DTLS_H
