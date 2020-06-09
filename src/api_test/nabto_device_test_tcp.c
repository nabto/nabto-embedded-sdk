#include <nabto/nabto_device_test.h>

#include <api/nabto_device_future.h>
#include <api/nabto_device_error.h>
#include <api/nabto_device_defines.h>

#include <platform/np_tcp_wrapper.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_completion_event.h>
#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_TEST

static uint8_t sendBuffer[] = {1,2,3,4};

struct tcp_test {
    struct nabto_device_future* fut;
    struct np_tcp tcp;
    struct np_event_queue eq;
    struct np_tcp_socket* sock;
    struct np_completion_event completionEvent;
    struct np_ip_address ip;
    struct np_event* timeoutEvent;
    uint8_t readBuffer[4];
    size_t readLength;
    size_t bytesRead;
};

static void start_read(struct tcp_test* t);

static void resolve_and_free_test(struct tcp_test* t, np_error_code ec)
{
    nabto_device_future_resolve(t->fut, nabto_device_error_core_to_api(ec));

    np_completion_event_deinit(&t->completionEvent);
    np_event_queue_destroy_event(&t->eq, t->timeoutEvent);
    np_tcp_destroy(&t->tcp, t->sock);
    free(t);
}

static void timeout(void* data)
{
    struct tcp_test* t = data;
    NABTO_LOG_ERROR(LOG, "TCP test took too long, aborting test.");
    np_tcp_abort(&t->tcp, t->sock);
}

static void data_ready(np_error_code ec, void* data)
{
    struct tcp_test* t = data;
    if (ec) {
        return resolve_and_free_test(t, ec);
    }
    t->bytesRead += t->readLength;
    if (t->bytesRead > sizeof(t->readBuffer)) {
        NABTO_LOG_ERROR(LOG, "The amount of data read is larger than the size of the buffer.");
        return resolve_and_free_test(t, NABTO_EC_INVALID_STATE);
    }
    if (t->bytesRead < sizeof(t->readBuffer)) {
        return start_read(t);
    }

    // else all data is read
    if (memcmp(t->readBuffer, sendBuffer, sizeof(sendBuffer)) != 0) {
        NABTO_LOG_ERROR(LOG, "Received TCP data does not match the data sent.");
        return resolve_and_free_test(t, NABTO_EC_INVALID_STATE);
    }

    resolve_and_free_test(t, NABTO_EC_OK);
}

static void start_read(struct tcp_test* t)
{
    np_completion_event_reinit(&t->completionEvent, &data_ready, t);
    size_t totalReadLength = sizeof(sendBuffer);
    size_t missingReadLength = totalReadLength - t->bytesRead;
    uint8_t* readBufferCurrent = t->readBuffer + t->bytesRead;
    np_tcp_async_read(&t->tcp, t->sock, readBufferCurrent, missingReadLength, &t->readLength, &t->completionEvent);
}

static void data_sent(np_error_code ec, void* data)
{
    struct tcp_test* t = data;
    if (ec) {
        return resolve_and_free_test(t, ec);
    }
    start_read(t);
}

static void socket_connected(np_error_code ec, void* data)
{
    struct tcp_test* t = data;
    if (ec) {
        return resolve_and_free_test(t, ec);
    }
    np_completion_event_reinit(&t->completionEvent, &data_sent, t);
    np_tcp_async_write(&t->tcp, t->sock, sendBuffer, sizeof(sendBuffer), &t->completionEvent);

}

void NABTO_DEVICE_API
nabto_device_test_tcp(NabtoDevice* device, const char* ip, uint16_t port, NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    struct tcp_test* t = calloc(1, sizeof(struct tcp_test));
    if (t == NULL) {
        return nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OUT_OF_MEMORY);
    }

    if (!np_ip_address_read_v4(ip, &t->ip))
    {
        return resolve_and_free_test(t, NABTO_EC_INVALID_ARGUMENT);
    }

    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    t->fut = fut;
    t->tcp = dev->pl.tcp;
    t->eq = dev->pl.eq;

    np_error_code ec;
    ec = np_tcp_create(&t->tcp, &t->sock);
    if (ec != NABTO_EC_OK) {
        return resolve_and_free_test(t, ec);
    }

    ec = np_completion_event_init(&dev->pl.eq, &t->completionEvent, &socket_connected, t);
    if (ec != NABTO_EC_OK) {
        return resolve_and_free_test(t, ec);
    }

    ec = np_event_queue_create_event(&t->eq, timeout, t, &t->timeoutEvent);
    if (ec != NABTO_EC_OK) {
        return resolve_and_free_test(t, ec);
    }

    np_tcp_async_connect(&t->tcp, t->sock, &t->ip, port, &t->completionEvent);

    // set a 5 seconds timeout on the test.
    np_event_queue_post_timed_event(&t->eq, t->timeoutEvent, 5000);
}
