#ifndef THERMOSTAT_STREAM_H_
#define THERMOSTAT_STREAM_H_

#include <nabto/nabto_device.h>

#include <pthread.h>
#include <stdbool.h>

/**
 * State change stream. Clients open a nabto stream on port 655 and the device
 * pushes the full thermostat state to the client whenever the state changes.
 * Each message is a 4 byte big endian unsigned length followed by that many
 * bytes of CBOR encoded state, the CBOR map is identical to the response of
 * GET /thermostat. Data sent by the client is read and discarded, it is only
 * used to detect that the client has closed the stream.
 */

struct thermostat;
struct thermostat_stream;

struct thermostat_stream_manager {
    NabtoDevice* device;
    struct thermostat* thermostat;
    NabtoDeviceListener* listener;
    NabtoDeviceFuture* listenFuture;
    NabtoDeviceStream* newStream;
    struct thermostat_stream* streams;
    // protects the stream list and the per stream send state which is
    // accessed from both the main thread and the nabto device threads.
    pthread_mutex_t mutex;
};

NabtoDeviceError thermostat_stream_manager_init(struct thermostat_stream_manager* manager, NabtoDevice* device, struct thermostat* thermostat);
void thermostat_stream_manager_stop(struct thermostat_stream_manager* manager);
void thermostat_stream_manager_deinit(struct thermostat_stream_manager* manager);

/**
 * Mark the state dirty on all open streams and attempt to send. Called by the
 * state changed observer.
 */
void thermostat_stream_manager_notify_state_changed(struct thermostat_stream_manager* manager);

/**
 * Attempt to send on streams with pending changes, called periodically from
 * the tick loop such that throttled updates get sent.
 */
void thermostat_stream_manager_flush(struct thermostat_stream_manager* manager);

#endif
