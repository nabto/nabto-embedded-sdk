#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>
#include <api/nabto_device_error.h>
#include <api/nabto_device_future.h>

#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>
#include <platform/np_udp_wrapper.h>

#define LOG NABTO_LOG_MODULE_TEST

static uint8_t sendBuffer[] = {1,2,3,4};

struct udp_test {
    struct nabto_device_future* fut;
    struct np_udp udp;
    struct np_event_queue eq;
    struct np_udp_socket* sock;
    struct np_completion_event completionEvent;
    struct np_udp_endpoint ep;
    struct np_event* timeoutEvent;
    uint8_t recvBuffer[1500];
};

static void resolve_and_free_test(struct udp_test* t, np_error_code ec)
{
    nabto_device_future_resolve(t->fut, nabto_device_error_core_to_api(ec));

    np_completion_event_deinit(&t->completionEvent);
    np_event_queue_cancel_event(&t->eq, t->timeoutEvent);
    np_event_queue_destroy_event(&t->eq, t->timeoutEvent);
    np_udp_destroy(&t->udp, t->sock);
    np_free(t);
}

static void timeout(void* data)
{
    struct udp_test* t = data;
    NABTO_LOG_ERROR(LOG, "UDP test took too long, aborting test.");
    np_udp_abort(&t->udp, t->sock);
}

static void packet_ready(np_error_code ec, void* data)
{
    struct udp_test* t = data;
    if (ec) {
        resolve_and_free_test(t, ec);
        return;
    }
    struct np_udp_endpoint recvEp;
    uint8_t recvBuffer[1500];
    size_t recvSize = 0;
    np_error_code recvEc = np_udp_recv_from(&t->udp, t->sock, &recvEp, recvBuffer, 1500, &recvSize);
    if (recvEc != NABTO_EC_OK) {
        resolve_and_free_test(t, recvEc);
        return;
    }

    size_t sendSize = sizeof(sendBuffer);
    if (recvSize != sendSize) {
        NABTO_LOG_ERROR(LOG, "Invalid size of received udp packet");
        resolve_and_free_test(t, NABTO_EC_INVALID_STATE);
        return;
    }

    if (memcmp(recvBuffer, sendBuffer, sendSize) != 0) {
        NABTO_LOG_ERROR(LOG, "Received udp data does not match the data sent.");
        resolve_and_free_test(t, NABTO_EC_INVALID_STATE);
        return;
    }

    resolve_and_free_test(t, NABTO_EC_OK);
}

static void packet_sent(np_error_code ec, void* data)
{
    struct udp_test* t = data;
    if (ec) {
        resolve_and_free_test(t, ec);
        return;
    }
    np_completion_event_reinit(&t->completionEvent, &packet_ready, t);
    np_udp_async_recv_wait(&t->udp, t->sock, &t->completionEvent);
}

static void socket_bound(np_error_code ec, void* data)
{
    struct udp_test* t = data;
    if (ec) {
        resolve_and_free_test(t, ec);
        return;
    }
    np_completion_event_reinit(&t->completionEvent, &packet_sent, t);
    np_udp_async_send_to(&t->udp, t->sock, &t->ep, sendBuffer, sizeof(sendBuffer), &t->completionEvent);

}

void NABTO_DEVICE_API
nabto_device_test_udp(NabtoDevice* device, const char* ip, uint16_t port, NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    struct udp_test* t = np_calloc(1, sizeof(struct udp_test));
    nabto_device_future_reset(fut);
    if (t == NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OUT_OF_MEMORY);
        return;
    }

    t->fut = fut;

    if (!np_ip_address_read_v4(ip, &t->ep.ip))
    {
        resolve_and_free_test(t, NABTO_EC_INVALID_ARGUMENT);
        return;
    }

    t->ep.port = port;

    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    t->udp = dev->pl.udp;
    t->eq = dev->pl.eq;

    np_error_code ec = np_udp_create(&t->udp, &t->sock);
    if (ec != NABTO_EC_OK) {
        resolve_and_free_test(t, ec);
        return;
    }

    ec = np_completion_event_init(&dev->pl.eq, &t->completionEvent, &socket_bound, t);
    if (ec != NABTO_EC_OK) {
        resolve_and_free_test(t, ec);
        return;
    }

    ec = np_event_queue_create_event(&t->eq, timeout, t, &t->timeoutEvent);
    if (ec != NABTO_EC_OK) {
        resolve_and_free_test(t, ec);
        return;
    }

    np_udp_async_bind_port(&t->udp, t->sock, 0, &t->completionEvent);

    // set a 5 seconds timeout on the test.
    np_event_queue_post_timed_event(&t->eq, t->timeoutEvent, 5000);
}
