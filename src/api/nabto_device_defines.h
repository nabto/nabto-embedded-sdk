#ifndef NABTO_DEVICE_DEFINES_H
#define NABTO_DEVICE_DEFINES_H

#include "nabto_device_threads.h"

#include <platform/np_platform.h>
#include <core/nc_device.h>
#include <modules/tcptunnel/nm_tcptunnel.h>
#include <modules/mdns/nm_mdns.h>

NabtoDeviceError nabto_device_error_core_to_api(np_error_code ec);

struct nabto_device_coap_resource;
struct nm_tcptunnels;

struct nabto_device_context {
    struct np_platform pl;
    struct nc_device_context core;

    struct nabto_device_thread* coreThread;
    struct nabto_device_thread* networkThread;
    struct nabto_device_mutex* eventMutex;
    struct nabto_device_condition* eventCond;
    struct nabto_device_future* iamChangedFuture;

    bool enableMdns;
    struct nm_mdns mdns;

    bool closing;

    struct nabto_device_future* queueHead;
    struct nabto_device_coap_resource* coapResourceHead;

    struct nabto_device_future* streamListenFuture;
    struct nabto_device_stream** streamListenStream;

    char appName[33];
    char appVersion[33];

    char* productId;
    char* deviceId;
    char* serverUrl;
    char* publicKey;
    char* privateKey;
    uint16_t port;

    struct nabto_device_future* closeFut;

    struct nm_tcptunnels tcptunnels;
};



#endif //NABTO_DEVICE_DEFINES_H
