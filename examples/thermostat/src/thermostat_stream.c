#include "thermostat_stream.h"
#include "thermostat.h"
#include "thermostat_state.h"

#include <modules/iam/nm_iam.h>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define THERMOSTAT_STREAM_PORT 655
#define THERMOSTAT_STREAM_MIN_SEND_INTERVAL_MS 1000
#define THERMOSTAT_STREAM_TEMPERATURE_DELTA 0.05
#define THERMOSTAT_STREAM_READ_BUFFER_SIZE 256

struct thermostat_stream {
    struct thermostat_stream_manager* manager;
    NabtoDeviceStream* stream;
    struct thermostat_stream* next;
    uint8_t readBuffer[THERMOSTAT_STREAM_READ_BUFFER_SIZE];
    size_t readLength;
    uint8_t* writeBuffer;
    bool accepted;
    bool writing;
    bool dirty;
    bool ended;
    int pendingOps;
    bool sentAny;
    uint64_t lastSentMs;
    double lastTemperature;
    double lastTarget;
    bool lastPower;
    enum thermostat_mode lastMode;
    struct thermostat_schedule lastSchedule;
};

static void start_listen(struct thermostat_stream_manager* manager);
static void new_stream_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void accepted_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void read_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void write_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void start_read_locked(struct thermostat_stream* ts);
static void try_send_locked(struct thermostat_stream* ts);
static void try_free_locked(struct thermostat_stream* ts);

static uint64_t monotonic_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000) + ((uint64_t)ts.tv_nsec / 1000000);
#endif
}

NabtoDeviceError thermostat_stream_manager_init(struct thermostat_stream_manager* manager, NabtoDevice* device, struct thermostat* thermostat)
{
    memset(manager, 0, sizeof(struct thermostat_stream_manager));
    manager->device = device;
    manager->thermostat = thermostat;
    thermostat_mutex_init(&manager->mutex);

    manager->listenFuture = nabto_device_future_new(device);
    manager->listener = nabto_device_listener_new(device);
    if (manager->listenFuture == NULL || manager->listener == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    NabtoDeviceError ec = nabto_device_stream_init_listener(device, manager->listener, THERMOSTAT_STREAM_PORT);
    if (ec == NABTO_DEVICE_EC_OK) {
        start_listen(manager);
    }
    return ec;
}

void thermostat_stream_manager_stop(struct thermostat_stream_manager* manager)
{
    if (manager->device == NULL) {
        return;
    }
    if (manager->listener != NULL) {
        nabto_device_listener_stop(manager->listener);
    }
    thermostat_mutex_lock(&manager->mutex);
    struct thermostat_stream* ts = manager->streams;
    while (ts != NULL) {
        nabto_device_stream_abort(ts->stream);
        ts = ts->next;
    }
    thermostat_mutex_unlock(&manager->mutex);
}

void thermostat_stream_manager_deinit(struct thermostat_stream_manager* manager)
{
    if (manager->device == NULL) {
        return;
    }
    // at this point the device has been stopped so all futures have been
    // resolved and the streams have freed themselves.
    if (manager->listenFuture != NULL) {
        nabto_device_future_free(manager->listenFuture);
    }
    if (manager->listener != NULL) {
        nabto_device_listener_free(manager->listener);
    }
    thermostat_mutex_destroy(&manager->mutex);
    manager->device = NULL;
}

void thermostat_stream_manager_notify_state_changed(struct thermostat_stream_manager* manager)
{
    if (manager->device == NULL) {
        return;
    }
    thermostat_mutex_lock(&manager->mutex);
    struct thermostat_stream* ts = manager->streams;
    while (ts != NULL) {
        ts->dirty = true;
        try_send_locked(ts);
        ts = ts->next;
    }
    thermostat_mutex_unlock(&manager->mutex);
}

void thermostat_stream_manager_flush(struct thermostat_stream_manager* manager)
{
    if (manager->device == NULL) {
        return;
    }
    thermostat_mutex_lock(&manager->mutex);
    struct thermostat_stream* ts = manager->streams;
    while (ts != NULL) {
        try_send_locked(ts);
        ts = ts->next;
    }
    thermostat_mutex_unlock(&manager->mutex);
}

void start_listen(struct thermostat_stream_manager* manager)
{
    nabto_device_listener_new_stream(manager->listener, manager->listenFuture, &manager->newStream);
    nabto_device_future_set_callback(manager->listenFuture, new_stream_callback, manager);
}

void new_stream_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    (void)future;
    struct thermostat_stream_manager* manager = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        // the listener has been stopped, do not rearm.
        return;
    }
    NabtoDeviceStream* stream = manager->newStream;
    manager->newStream = NULL;

    NabtoDeviceConnectionRef ref = nabto_device_stream_get_connection_ref(stream);
    if (!nm_iam_check_access(manager->thermostat->iam, ref, "Thermostat:Get", NULL)) {
        // access denied, the stream is freed without being accepted so the
        // open fails in the client.
        nabto_device_stream_free(stream);
    } else {
        struct thermostat_stream* ts = calloc(1, sizeof(struct thermostat_stream));
        NabtoDeviceFuture* acceptFuture = nabto_device_future_new(manager->device);
        if (ts == NULL || acceptFuture == NULL) {
            free(ts);
            if (acceptFuture != NULL) {
                nabto_device_future_free(acceptFuture);
            }
            nabto_device_stream_free(stream);
        } else {
            ts->manager = manager;
            ts->stream = stream;
            thermostat_mutex_lock(&manager->mutex);
            ts->next = manager->streams;
            manager->streams = ts;
            ts->pendingOps = 1;
            thermostat_mutex_unlock(&manager->mutex);
            nabto_device_stream_accept(stream, acceptFuture);
            nabto_device_future_set_callback(acceptFuture, accepted_callback, ts);
        }
    }
    start_listen(manager);
}

void accepted_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct thermostat_stream* ts = userData;
    struct thermostat_stream_manager* manager = ts->manager;
    thermostat_mutex_lock(&manager->mutex);
    ts->pendingOps--;
    if (ec != NABTO_DEVICE_EC_OK) {
        ts->ended = true;
        try_free_locked(ts);
    } else {
        ts->accepted = true;
        ts->dirty = true;
        // send the full state immediately after accept.
        try_send_locked(ts);
        // start_read_locked may free ts on failure so it must be the last
        // use of ts.
        start_read_locked(ts);
    }
    thermostat_mutex_unlock(&manager->mutex);
}

void start_read_locked(struct thermostat_stream* ts)
{
    NabtoDeviceFuture* readFuture = nabto_device_future_new(ts->manager->device);
    if (readFuture == NULL) {
        ts->ended = true;
        nabto_device_stream_abort(ts->stream);
        try_free_locked(ts);
        return;
    }
    ts->pendingOps++;
    nabto_device_stream_read_some(ts->stream, readFuture, ts->readBuffer, THERMOSTAT_STREAM_READ_BUFFER_SIZE, &ts->readLength);
    nabto_device_future_set_callback(readFuture, read_callback, ts);
}

void read_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct thermostat_stream* ts = userData;
    struct thermostat_stream_manager* manager = ts->manager;
    thermostat_mutex_lock(&manager->mutex);
    ts->pendingOps--;
    if (ec != NABTO_DEVICE_EC_OK) {
        // EOF or error, the client is gone.
        ts->ended = true;
        nabto_device_stream_abort(ts->stream);
        try_free_locked(ts);
    } else {
        // discard the read data, read again to detect EOF.
        start_read_locked(ts);
    }
    thermostat_mutex_unlock(&manager->mutex);
}

static bool schedule_entry_equals(const struct thermostat_schedule_entry* a, const struct thermostat_schedule_entry* b)
{
    return a->target == b->target &&
           a->enabled == b->enabled &&
           strncmp(a->time, b->time, sizeof(a->time)) == 0;
}

static bool state_changed(struct thermostat_stream* ts, double temperature, double target, bool power, enum thermostat_mode mode, const struct thermostat_schedule* schedule)
{
    if (fabs(temperature - ts->lastTemperature) >= THERMOSTAT_STREAM_TEMPERATURE_DELTA) {
        return true;
    }
    if (target != ts->lastTarget || power != ts->lastPower || mode != ts->lastMode) {
        return true;
    }
    if (!schedule_entry_equals(&schedule->day, &ts->lastSchedule.day) ||
        !schedule_entry_equals(&schedule->night, &ts->lastSchedule.night))
    {
        return true;
    }
    return false;
}

void try_send_locked(struct thermostat_stream* ts)
{
    if (!ts->accepted || ts->ended || ts->writing || !ts->dirty) {
        return;
    }
    uint64_t now = monotonic_ms();
    if (ts->sentAny && (now - ts->lastSentMs) < THERMOSTAT_STREAM_MIN_SEND_INTERVAL_MS) {
        // throttled, the dirty flag stays set and the send is retried from
        // the flush called by the tick loop.
        return;
    }

    struct thermostat_state* state = ts->manager->thermostat->state;
    double temperature = thermostat_state_get_temperature(state);
    double target = thermostat_state_get_target(state);
    bool power = thermostat_state_get_power(state);
    enum thermostat_mode mode = thermostat_state_get_mode(state);
    struct thermostat_schedule schedule;
    thermostat_state_get_schedule(state, &schedule);

    if (ts->sentAny && !state_changed(ts, temperature, target, power, mode, &schedule)) {
        ts->dirty = false;
        return;
    }

    // Encode once: the tick thread can change state between sizing and writing.
    const size_t capacity = THERMOSTAT_STATE_CBOR_CAPACITY;
    uint8_t* buffer = malloc(4 + capacity);
    if (buffer == NULL) {
        ts->dirty = false;
        return;
    }
    size_t cborSize = thermostat_state_encode(state, buffer + 4, capacity);
    if (cborSize == 0) {
        free(buffer);
        return;
    }
    buffer[0] = (uint8_t)((cborSize >> 24) & 0xff);
    buffer[1] = (uint8_t)((cborSize >> 16) & 0xff);
    buffer[2] = (uint8_t)((cborSize >> 8) & 0xff);
    buffer[3] = (uint8_t)(cborSize & 0xff);

    NabtoDeviceFuture* writeFuture = nabto_device_future_new(ts->manager->device);
    if (writeFuture == NULL) {
        free(buffer);
        ts->dirty = false;
        return;
    }

    ts->writeBuffer = buffer;
    ts->writing = true;
    ts->dirty = false;
    ts->sentAny = true;
    ts->lastSentMs = now;
    ts->lastTemperature = temperature;
    ts->lastTarget = target;
    ts->lastPower = power;
    ts->lastMode = mode;
    ts->lastSchedule = schedule;

    ts->pendingOps++;
    nabto_device_stream_write(ts->stream, writeFuture, ts->writeBuffer, 4 + cborSize);
    nabto_device_future_set_callback(writeFuture, write_callback, ts);
}

void write_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct thermostat_stream* ts = userData;
    struct thermostat_stream_manager* manager = ts->manager;
    thermostat_mutex_lock(&manager->mutex);
    ts->pendingOps--;
    ts->writing = false;
    free(ts->writeBuffer);
    ts->writeBuffer = NULL;
    if (ec != NABTO_DEVICE_EC_OK) {
        ts->ended = true;
        nabto_device_stream_abort(ts->stream);
    }
    if (ts->ended) {
        try_free_locked(ts);
    } else {
        // the state may have changed while the write was outstanding.
        try_send_locked(ts);
    }
    thermostat_mutex_unlock(&manager->mutex);
}

void try_free_locked(struct thermostat_stream* ts)
{
    if (!ts->ended || ts->pendingOps != 0) {
        return;
    }
    struct thermostat_stream_manager* manager = ts->manager;
    struct thermostat_stream** iterator = &manager->streams;
    while (*iterator != NULL && *iterator != ts) {
        iterator = &((*iterator)->next);
    }
    if (*iterator == ts) {
        *iterator = ts->next;
    }
    nabto_device_stream_free(ts->stream);
    free(ts->writeBuffer);
    free(ts);
}
