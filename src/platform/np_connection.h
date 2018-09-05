#ifndef NP_CONNECTION_H
#define NP_CONNECTION_H

#include <nabto_types.h>

#include <platform/np_error_code.h>
#include <platform/np_event_queue.h>
#include <platform/np_udp.h>
#include <platform/np_communication_buffer.h>

struct np_platform;

typedef struct np_connection np_connection;
struct np_connection_id {
    uint8_t id[16];
};

typedef void (*np_connection_created_callback)(const np_error_code ec, uint8_t channelId, void* data);

typedef void (*np_connection_sent_callback)(const np_error_code ec, void* data);

typedef void (*np_connection_received_callback)(const np_error_code ec, struct np_connection* conn,
                                                uint8_t channelId, np_communication_buffer* buffer,
                                                uint16_t bufferSize, void* data);

typedef void (*np_connection_destroyed_callback)(const np_error_code ec, void* data);

struct np_connection_channel {
    enum np_channel_type type;
    struct np_udp_socket* sock;
    np_udp_endpoint ep;
    uint8_t channelId;
};

#define NABTO_CONNECTION_MAX_CHANNELS 16

struct np_connection {
    struct np_connection_channel channels[NABTO_CONNECTION_MAX_CHANNELS]; // several application channels can exist
    struct np_platform* pl;
    struct np_event ev;
    struct np_connection_id id;
    np_error_code ec;
    np_connection_created_callback createCb;
    void* createData;
    np_connection_sent_callback sentCb;
    np_udp_endpoint sentEp;
    void* sentData;
    np_connection_received_callback recvCb;
    void* recvData;
    np_connection_destroyed_callback desCb;
    void* desData;
};

struct np_connection_module {
    void (*async_create)(struct np_platform* pl, np_connection* conn, struct np_connection_channel* channel,
                         struct np_connection_id* id, np_connection_created_callback cb, void* data);

    np_error_code (*add_channel)(struct np_platform* pl, np_connection* conn,
                                 struct np_connection_channel* channel);

    np_error_code (*rem_channel)(struct np_platform* pl, np_connection* conn, uint8_t channelId);

    struct np_connection_id* (*get_id)(struct np_platform* pl, np_connection* conn);

    void (*async_send_to)(struct np_platform* pl, np_connection* conn, uint8_t channelId,
                          np_communication_buffer* buffer, uint16_t bufferSize,
                          np_connection_sent_callback cb, void* data);

    void (*async_recv_from)(struct np_platform* pl, np_connection* conn,
                            np_connection_received_callback cb, void* data);

    np_error_code (*cancel_async_recv)(struct np_platform* pl, np_connection* conn);
    np_error_code (*cancel_async_send)(struct np_platform* pl, np_connection* conn);

    void (*async_destroy)(struct np_platform* pl, np_connection* conn,
                          np_connection_destroyed_callback cb, void* data);
};

#endif //NP_CONNNECTION_H
