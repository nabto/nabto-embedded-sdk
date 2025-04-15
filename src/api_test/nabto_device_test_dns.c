#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>
#include <api/nabto_device_error.h>
#include <api/nabto_device_future.h>

#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_dns_wrapper.h>
#include <platform/np_ip_address.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_TEST

struct dns_test {
    struct nabto_device_future* fut;
    struct np_dns dns;
    struct np_completion_event completionEvent;
    struct np_ip_address dnsResults[4];
    size_t resolvedIps;
};


// ip.test.dev.nabto.com resolves to ipv4: 1.2.3.4, ipv6: 2001:db8::1
const char* dnsName = "ip.test.dev.nabto.com";
uint8_t ipv4[4] = {1,2,3,4};
uint8_t ipv6[16] = {0x20, 0x01, 0x0d, 0xb8,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01 };

static void ipv6_resolved_callback(np_error_code ec, void* data);
static void ipv4_resolved_callback(np_error_code ec, void* data);

static void resolve_and_free_test(struct dns_test* t, np_error_code ec)
{
    nabto_device_future_resolve(t->fut, nabto_device_error_core_to_api(ec));
    np_completion_event_deinit(&t->completionEvent);
    np_free(t);
}

static void start_ipv4_test(struct dns_test* t)
{
    np_completion_event_reinit(&t->completionEvent, ipv4_resolved_callback, t);
    np_dns_async_resolve_v4(&t->dns, dnsName, t->dnsResults, 4, &t->resolvedIps, &t->completionEvent);
}

static void start_ipv6_test(struct dns_test* t)
{
    np_completion_event_reinit(&t->completionEvent, ipv6_resolved_callback, t);
    np_dns_async_resolve_v6(&t->dns, dnsName, t->dnsResults, 4, &t->resolvedIps, &t->completionEvent);
}

static void ipv6_resolved_callback(np_error_code ec, void* data)
{
    struct dns_test* t = data;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "ipv6 dns resolution failed %s", np_error_code_to_string(ec));
    } else if (t->resolvedIps != 1) {
        NABTO_LOG_ERROR(LOG, "The number of resolved ipv6 addresses should be 1 but it was %d", t->resolvedIps);
        ec = NABTO_EC_INVALID_STATE;
    } else if (t->dnsResults[0].type != NABTO_IPV6) {
        NABTO_LOG_ERROR(LOG, "The type of the resolved ipv6 address is wrong");
        ec = NABTO_EC_INVALID_STATE;
    } else if (memcmp(t->dnsResults[0].ip.v6, ipv6, 16) != 0) {
        NABTO_LOG_ERROR(LOG, "The resolved ip is not 2001:db8::1");
        ec = NABTO_EC_INVALID_STATE;
    } else {
        // No errors
        ec = NABTO_EC_OK;
    }
    // handle the error or ok result.
    resolve_and_free_test(t, ec);

}

static void ipv4_resolved_callback(np_error_code ec, void* data)
{
    struct dns_test* t = data;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "ipv4 dns resolution failed %s", np_error_code_to_string(ec));
    } else if (t->resolvedIps != 1) {
        NABTO_LOG_ERROR(LOG, "The number of resolved ipv4 addresses should be 1 but it was %d", t->resolvedIps);
        ec = NABTO_EC_INVALID_STATE;
    } else if (t->dnsResults[0].type != NABTO_IPV4) {
        NABTO_LOG_ERROR(LOG, "The type of the resolved ipv4 address is wrong");
        ec = NABTO_EC_INVALID_STATE;
    } else if (memcmp(t->dnsResults[0].ip.v4, ipv4, 4) != 0) {
        NABTO_LOG_ERROR(LOG, "The resolved ip is not 1.2.3.4");
        ec = NABTO_EC_INVALID_STATE;
    } else {
        // No errors
        start_ipv6_test(t);
        return;
    }
    // handle the error
    resolve_and_free_test(t, ec);
}

void NABTO_DEVICE_API
nabto_device_test_dns(NabtoDevice* device, NabtoDeviceFuture* future)
{
    struct dns_test* t = np_calloc(1, sizeof(struct dns_test));
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_future_reset(fut);
    if (t == NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OUT_OF_MEMORY);
        return;
    }

    t->fut = fut;
    t->dns = dev->pl.dns;
    np_error_code ec = np_completion_event_init(&dev->pl.eq, &t->completionEvent, NULL, NULL);
    if (ec != NABTO_EC_OK) {
        resolve_and_free_test(t, ec);
    } else {
        start_ipv4_test(t);
    }
}
