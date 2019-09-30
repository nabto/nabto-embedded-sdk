#ifndef _NC_CONNECTION_EVENT_H_
#define _NC_CONNECTION_EVENT_H_

enum nc_connection_event {
    NC_CONNECTION_EVENT_OPENED,
    NC_CONNECTION_EVENT_CLOSED,
    NC_CONNECTION_EVENT_CHANNEL_CHANGED
};

typedef void (*nc_connection_event_callback)(uint64_t connectionRef, enum nc_connection_event event, void* userData);

struct nc_connection_events_listener;
struct nc_connection_events_listener {
    struct nc_connection_events_listener* next;
    struct nc_connection_events_listener* prev;

    nc_connection_event_callback cb;
    void* userData;
};

#endif
