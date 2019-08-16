#ifndef NABTO_DEVICE_STREAM_H
#define NABTO_DEVICE_STREAM_H

#include <nabto/nabto_device.h>
#include <api/nabto_api_future_queue.h>

#include <core/nc_device.h>

struct nabto_device_context;

struct nabto_device_stream {
    struct nabto_stream* stream;
    struct nabto_device_future* acceptFut;
    struct nabto_device_future* listenFut;
    struct nabto_device_future* readSomeFut;
    struct nabto_device_future* readAllFut;
    uint8_t* readBuffer;
    size_t readBufferLength;
    size_t* readLength;

    struct nabto_device_future* writeFut;
    const uint8_t* writeBuffer;
    size_t writeBufferLength;

    struct nabto_device_future* closeFut;
    struct nabto_device_context* dev;

    // coordinate freeing of this context which can both be initiated by the user and by the system
    bool readyToFree;
};

void nabto_device_stream_listener_callback(struct nabto_stream* stream, void* data);
void nabto_device_stream_application_event_callback(nabto_stream_application_event_type eventType, void* data);
void nabto_device_stream_do_read(struct nabto_device_stream* str);
void nabto_device_stream_do_write_all(struct nabto_device_stream* str);
void nabto_device_stream_handle_close(struct nabto_device_stream* str);



#endif // NABTO_DEVICE_STREAM_H
