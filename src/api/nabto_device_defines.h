#ifndef NABTO_DEVICE_DEFINES_H
#define NABTO_DEVICE_DEFINES_H

#include "nabto_device_threads.h"

#include <platform/np_platform.h>
#include <core/nc_device.h>
#include <modules/tcp_tunnel/nm_tcp_tunnel.h>
#include <nabto/nabto_device_experimental.h>
#include "nabto_device_authorization.h"
#include "nabto_device_future_queue.h"

#include <nn/llist.h>

struct nabto_device_coap_resource;
struct nm_tcp_tunnels;

struct nabto_device_context {
    struct np_platform pl;
    struct nc_device_context core;

    struct nabto_device_mutex* eventMutex;

    struct nn_llist listeners;

    bool enableMdns;

    bool closing;

    struct nabto_device_future* queueHead;

    char appName[33];
    char appVersion[33];

    char* productId;
    char* deviceId;
    char* serverUrl;
    char* publicKey;
    char* privateKey;

    struct nabto_device_future* closeFut;

    struct nm_tcp_tunnels tcpTunnels;

    struct nabto_device_future_queue futureQueue;
    struct nabto_device_authorization_module authorization;

    void* platformAdapter;
};



#endif //NABTO_DEVICE_DEFINES_H
