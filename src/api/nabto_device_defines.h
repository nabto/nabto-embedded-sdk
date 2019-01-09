#ifndef NABTO_DEVICE_DEFINES_H
#define NABTO_DEVICE_DEFINES_H

#include <platform/np_platform.h>
#include <core/nc_device.h>
#include <pthread.h>

void nabto_api_future_set_error_code(NabtoDeviceFuture* future, const np_error_code ec);

struct nabto_device_context {
    struct np_platform pl;
    pthread_t coreThread;
    pthread_t networkThread;
    struct nc_device_context core;
    pthread_mutex_t eventMutex;
    pthread_cond_t eventCond;
    bool closing;

    NabtoDeviceFuture* queueHead;

    char appName[33];
    char appVersion[33];

    char* productId;
    char* deviceId;
    char* serverUrl;
    char* publicKey;
    char* privateKey;

    NabtoDeviceFuture* closeFut;
};



#endif //NABTO_DEVICE_DEFINES_H
