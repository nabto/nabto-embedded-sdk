#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>
#include <test_platform_libevent.hpp>

#include <core/nc_device.h>
#include <core/nc_stun.h>
#include <core/nc_udp_dispatch.h>
#include <platform/np_completion_event.h>
#include <platform/np_platform.h>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <util/test_owner.hpp>

namespace {
// Owner of the completion events and modules created by the tests.
nabto::test::TestOwner testOwner;
}

namespace {

// DNS mock which captures the resolve requests such that the test controls
// when and how they are resolved.
struct MockDns {
    struct np_ip_address* v4Ips = NULL;
    size_t* v4IpsResolved = NULL;
    struct np_completion_event* v4CompletionEvent = NULL;
    struct np_completion_event* v6CompletionEvent = NULL;
};

void mock_async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    (void)host; (void)ipsSize;
    MockDns* mock = (MockDns*)obj->data;
    mock->v4Ips = ips;
    mock->v4IpsResolved = ipsResolved;
    mock->v4CompletionEvent = completionEvent;
}

void mock_async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    (void)host; (void)ips; (void)ipsSize; (void)ipsResolved;
    MockDns* mock = (MockDns*)obj->data;
    mock->v6CompletionEvent = completionEvent;
}

struct np_dns_functions mockDnsModule = {
    &mock_async_resolve_v4,
    &mock_async_resolve_v6
};

// UDP mock which records sends and leaves them outstanding until the test
// resolves them.
struct MockUdp {
    std::mutex mutex;
    std::condition_variable cond;
    std::vector<struct np_completion_event*> sends;

    void waitForSends(size_t count)
    {
        std::unique_lock<std::mutex> lock(mutex);
        BOOST_REQUIRE(cond.wait_for(lock, std::chrono::seconds(5), [&] { return sends.size() >= count; }));
    }
    size_t sendCount()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return sends.size();
    }
};

MockUdp* mockUdp = NULL;

void mock_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* completionEvent)
{
    (void)sock; (void)ep; (void)buffer; (void)bufferSize;
    std::lock_guard<std::mutex> lock(mockUdp->mutex);
    mockUdp->sends.push_back(completionEvent);
    mockUdp->cond.notify_all();
}

struct np_udp_functions mockUdpModule;

np_error_code mock_random(struct np_platform* pl, void* buffer, size_t bufferSize)
{
    (void)pl;
    memset(buffer, 0x42, bufferSize);
    return NABTO_EC_OK;
}

void analyzeCallback(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    (void)ec; (void)res; (void)data;
}

}

BOOST_AUTO_TEST_SUITE(stun)

// A packet which arrives while a STUN request is being sent must not start
// another send. The send buffer and its completion event are still in use,
// and with lifetime checks enabled arming the event a second time aborts.
// Any UDP packet starting with 0x00 or 0x01 reaches the STUN client, so this
// can be triggered by anyone while an analysis is running.
BOOST_AUTO_TEST_CASE(packet_while_sending)
{
    auto tp = std::make_unique<nabto::test::TestPlatformLibevent>();
    struct np_platform* pl = tp->getPlatform();

    MockDns dns;
    pl->dns.mptr = &mockDnsModule;
    pl->dns.data = &dns;

    MockUdp udp;
    mockUdp = &udp;
    memset(&mockUdpModule, 0, sizeof(mockUdpModule));
    mockUdpModule.async_send_to = &mock_async_send_to;
    pl->udp.mptr = &mockUdpModule;
    pl->random.random = &mock_random;

    struct nc_udp_dispatch_context udpDispatch;
    memset(&udpDispatch, 0, sizeof(udpDispatch));
    udpDispatch.pl = pl;

    auto device = std::make_unique<struct nc_device_context>();
    struct nc_stun_context stun;
    BOOST_REQUIRE(nc_stun_init(&stun, device.get(), pl, &testOwner.ref) == NABTO_EC_OK);
    nc_stun_set_sockets(&stun, &udpDispatch, &udpDispatch);
    nc_stun_set_host(&stun, "stun.example.com", 3478);

    struct nc_stun_callback callback;
    nabto_device_threads_mutex_lock(tp->getMutex());
    BOOST_TEST(nc_stun_async_analyze_simple(&stun, &callback, &analyzeCallback, NULL) == NABTO_EC_OK);

    // Two STUN endpoints, so the initial test is sent twice, the second send
    // started when the first completes.
    for (uint8_t i = 0; i < 2; i++) {
        dns.v4Ips[i].type = NABTO_IPV4;
        uint8_t ip[4] = { 192, 0, 2, (uint8_t)(1 + i) };
        memcpy(dns.v4Ips[i].ip.v4, ip, 4);
    }
    *dns.v4IpsResolved = 2;
    np_completion_event_resolve(dns.v4CompletionEvent, NABTO_EC_OK);
    np_completion_event_resolve(dns.v6CompletionEvent, NABTO_EC_UNKNOWN);
    nabto_device_threads_mutex_unlock(tp->getMutex());

    udp.waitForSends(1);

    // A packet with an unknown transaction id while the first send is
    // outstanding.
    uint8_t packet[20];
    memset(packet, 0, sizeof(packet));
    struct np_udp_endpoint ep;
    memset(&ep, 0, sizeof(ep));
    nabto_device_threads_mutex_lock(tp->getMutex());
    nc_stun_handle_packet(&stun, &ep, packet, sizeof(packet));
    nabto_device_threads_mutex_unlock(tp->getMutex());
    BOOST_TEST(udp.sendCount() == (size_t)1);

    // The second send is started when the first completes.
    nabto_device_threads_mutex_lock(tp->getMutex());
    np_completion_event_resolve(udp.sends[0], NABTO_EC_OK);
    nabto_device_threads_mutex_unlock(tp->getMutex());
    udp.waitForSends(2);
    BOOST_TEST(udp.sendCount() == (size_t)2);

    // Clean up. The outstanding send has to complete before deinit.
    nabto_device_threads_mutex_lock(tp->getMutex());
    nc_stun_stop(&stun);
    np_completion_event_resolve(udp.sends[1], NABTO_EC_OK);
    nabto_device_threads_mutex_unlock(tp->getMutex());
    for (;;) {
        nabto_device_threads_mutex_lock(tp->getMutex());
        bool armed = np_completion_event_is_armed(&stun.sendCompletionEvent);
        nabto_device_threads_mutex_unlock(tp->getMutex());
        if (!armed) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    nabto_device_threads_mutex_lock(tp->getMutex());
    nc_stun_deinit(&stun);
    nabto_device_threads_mutex_unlock(tp->getMutex());
    mockUdp = NULL;
}

BOOST_AUTO_TEST_SUITE_END()
