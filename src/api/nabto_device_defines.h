#ifndef NABTO_DEVICE_DEFINES_H
#define NABTO_DEVICE_DEFINES_H

#include "nabto_device_threads.h"

#include <platform/np_platform.h>
#include <platform/np_list.h>
#include <core/nc_device.h>
#include <modules/tcptunnel/nm_tcptunnel.h>
#include <nabto/nabto_device_experimental.h>
#include "nabto_device_authorization.h"

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

    struct nabto_device_mutex* futureQueueMutex;

    struct np_list listeners;

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
    uint16_t port;

    struct nabto_device_future* closeFut;

    struct nm_tcptunnels tcptunnels;

    struct nabto_device_authorization_module authorization;

};



#endif //NABTO_DEVICE_DEFINES_H
