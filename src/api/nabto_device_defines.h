#ifndef NABTO_DEVICE_DEFINES_H
#define NABTO_DEVICE_DEFINES_H

#include "nabto_device_threads.h"

#include "nabto_device_authorization.h"
#include "nabto_device_future_queue.h"
#include <core/nc_device.h>
#include <modules/tcp_tunnel/nm_tcp_tunnel.h>
#include <nabto/nabto_device_experimental.h>
#include <platform/np_platform.h>

#include <nn/llist.h>

struct nabto_device_coap_resource;
struct nm_tcp_tunnels;

/**
 * The time nabto_device_stop waits for closing connections, streams and
 * tunnels to finish the operations they have started, before the platform
 * is stopped.
 */
#ifndef NABTO_DEVICE_STOP_DRAIN_TIMEOUT_MS
#define NABTO_DEVICE_STOP_DRAIN_TIMEOUT_MS 2000
#endif

struct nabto_device_context {
    struct np_platform pl;
    struct nc_device_context core;

    struct nabto_device_mutex* eventMutex;
    // Signalled when no operations are outstanding, see np_ref_tracker.
    struct nabto_device_condition* drainCondition;

    struct nn_llist listeners;

    bool closing;

    struct nabto_device_future* queueHead;

    char* certificate;
    char* privateKey;
    uint8_t fingerprint[32];

    struct nabto_device_future* closeFut;
    struct np_completion_event platformCloseEvent;

    struct nabto_device_future* startFut;

    struct nm_tcp_tunnels tcpTunnels;

    struct nabto_device_future_queue futureQueue;
    struct nabto_device_authorization_module authorization;

    void* platformAdapter;
};



#endif //NABTO_DEVICE_DEFINES_H
