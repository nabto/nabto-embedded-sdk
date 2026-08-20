#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>
#include <test_platform_libevent.hpp>

#include <core/nc_dns_multi_resolver.h>
#include <platform/np_completion_event.h>
#include <platform/np_platform.h>

#include <future>

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

class CompletionWaiter {
 public:
    CompletionWaiter(struct np_platform* pl)
    {
        np_completion_event_init(&pl->eq, &completionEvent_, &CompletionWaiter::callback, this);
    }
    ~CompletionWaiter()
    {
        np_completion_event_deinit(&completionEvent_);
    }
    static void callback(const np_error_code ec, void* data)
    {
        CompletionWaiter* self = (CompletionWaiter*)data;
        self->promise_.set_value(ec);
    }
    np_error_code wait()
    {
        return promise_.get_future().get();
    }
    struct np_completion_event completionEvent_;
 private:
    std::promise<np_error_code> promise_;
};

}

BOOST_AUTO_TEST_SUITE(dns_multi_resolver)

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))

BOOST_AUTO_TEST_CASE(overlapping_resolve_is_rejected)
{
    auto tp = std::make_unique<nabto::test::TestPlatformLibevent>();
    struct np_platform* pl = tp->getPlatform();

    MockDns mock;
    pl->dns.mptr = &mockDnsModule;
    pl->dns.data = &mock;

    struct nc_dns_multi_resolver_context ctx;
    BOOST_TEST(nc_dns_multi_resolver_init(pl, &ctx) == NABTO_EC_OK);
    {
        CompletionWaiter first(pl);
        CompletionWaiter second(pl);

        struct np_ip_address ips[NC_DNS_MULTI_RESOLVER_MAX_IPS];
        size_t ipsResolved = 0;
        nc_dns_multi_resolver_resolve(&ctx, "example.com", ips, NC_DNS_MULTI_RESOLVER_MAX_IPS, &ipsResolved, &first.completionEvent_);
        BOOST_TEST(mock.v4CompletionEvent != (struct np_completion_event*)NULL);
        BOOST_TEST(mock.v6CompletionEvent != (struct np_completion_event*)NULL);

        // A resolve is outstanding, a second resolve must be rejected without
        // clobbering the in-flight state.
        struct np_ip_address ips2[NC_DNS_MULTI_RESOLVER_MAX_IPS];
        size_t ipsResolved2 = 0;
        nc_dns_multi_resolver_resolve(&ctx, "example.com", ips2, NC_DNS_MULTI_RESOLVER_MAX_IPS, &ipsResolved2, &second.completionEvent_);
        BOOST_TEST(second.wait() == NABTO_EC_OPERATION_IN_PROGRESS);

        // The outstanding resolve completes as usual.
        mock.v4Ips[0].type = NABTO_IPV4;
        memset(mock.v4Ips[0].ip.v6, 0, 16);
        mock.v4Ips[0].ip.v4[0] = 1;
        mock.v4Ips[0].ip.v4[1] = 2;
        mock.v4Ips[0].ip.v4[2] = 3;
        mock.v4Ips[0].ip.v4[3] = 4;
        *mock.v4IpsResolved = 1;
        np_completion_event_resolve(mock.v4CompletionEvent, NABTO_EC_OK);
        np_completion_event_resolve(mock.v6CompletionEvent, NABTO_EC_UNKNOWN);
        BOOST_TEST(first.wait() == NABTO_EC_OK);
        BOOST_TEST(ipsResolved == (size_t)1);
        BOOST_TEST(ctx.host == (char*)NULL);
    }
    nc_dns_multi_resolver_deinit(&ctx);
}

BOOST_AUTO_TEST_SUITE_END()
