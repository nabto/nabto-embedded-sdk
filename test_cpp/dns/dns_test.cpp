#include <boost/test/unit_test.hpp>
#include <test_platform.hpp>

#ifdef HAVE_EPOLL
#include <test_platform_epoll.hpp>
#endif

#ifdef HAVE_LIBEVENT
#include <test_platform_libevent.hpp>
#endif

namespace {

class DnsTest {
 public:
    DnsTest(nabto::test::TestPlatform& tp)
        : tp_(tp), pl_(tp.getPlatform())
    {
    }

    void start()
    {
        tp_.init();
        pl_->dns.async_resolve(pl_, dnsName_, &DnsTest::dnsCallback, this);
        tp_.run();
    }

    static void dnsCallback(const np_error_code ec, struct np_ip_address* v4Rec, size_t v4RecSize, struct np_ip_address* v6Rec, size_t v6RecSize, void* data)
    {
        BOOST_TEST(ec == NABTO_EC_OK);

        BOOST_TEST(v4RecSize == (size_t)1);
        BOOST_TEST(v6RecSize == (size_t)1);

        // ipv4 addr: 1.2.3.4

        uint8_t ipv4[4] = {1,2,3,4};

        BOOST_TEST(v4Rec[0].type == NABTO_IPV4);

        BOOST_TEST(memcmp(v4Rec[0].ip.v4, ipv4, 4) == 0);

        // ipv6 addr: 2001:db8::1
        uint8_t ipv6[16] = {0x20, 0x01, 0x0d, 0xb8,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x01 };

        BOOST_TEST(v6Rec[0].type == NABTO_IPV6);
        BOOST_TEST(memcmp(v6Rec[0].ip.v6, ipv6, 16) == 0);

        DnsTest* t = (DnsTest*)data;
        t->end();
    }

    void end() {
        tp_.stop();
    }

 private:
    const char* dnsName_ = "ip.test.dev.nabto.com";
    nabto::test::TestPlatform& tp_;
    struct np_platform* pl_;
};

}

BOOST_AUTO_TEST_SUITE(dns)

#ifdef HAVE_EPOLL

BOOST_AUTO_TEST_CASE(resolve_epoll, * boost::unit_test::timeout(30))
{
    nabto::test::TestPlatformEpoll epollPlatform;

    DnsTest dt(epollPlatform);
    dt.start();
}

#endif

#ifdef HAVE_LIBEVENT

BOOST_AUTO_TEST_CASE(resolve_libevent, * boost::unit_test::timeout(30))
{
    nabto::test::TestPlatformLibevent libeventPlatform;

    DnsTest dt(libeventPlatform);
    dt.start();
}

#endif

BOOST_AUTO_TEST_SUITE_END()
