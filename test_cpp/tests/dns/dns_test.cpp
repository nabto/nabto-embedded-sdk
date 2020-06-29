#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <test_platform.hpp>

#include <platform/np_error_code.h>
#include <platform/np_platform.h>
#include <platform/np_ip_address.h>
#include <platform/np_completion_event.h>
#include <platform/np_dns_wrapper.h>

#ifdef HAVE_LIBEVENT
#include <test_platform_libevent.hpp>
#endif

namespace {

class DnsTest {
 public:
    DnsTest(nabto::test::TestPlatform& tp)
        : tp_(tp), pl_(tp.getPlatform()), dns_(pl_->dns)
    {
        np_completion_event_init(&pl_->eq, &completionEvent_, &DnsTest::dnsCallback, this);
    }
    ~DnsTest()
    {
        np_completion_event_deinit(&completionEvent_);
    }
    static void dnsCallback(const np_error_code ec, void* data)
    {
        DnsTest* t = (DnsTest*)data;
        t->handleCallback(ec);
    }

    virtual void handleCallback(const np_error_code ec) = 0;

    void waitForTestEnd() {
        std::future<void> fut = testEnd_.get_future();
        fut.get();
    }
    void testEnded()
    {
        testEnd_.set_value();
    }

 protected:
    nabto::test::TestPlatform& tp_;
    struct np_platform* pl_;
    struct np_dns dns_;
    struct np_ip_address ips_[4];
    size_t ipsResolved_;
    struct np_completion_event completionEvent_;
    std::promise<void> testEnd_;
};


class DnsTestV4 : public DnsTest {
 public:
    DnsTestV4(nabto::test::TestPlatform& tp)
        : DnsTest(tp)
    {
    }

    void start()
    {
        np_dns_async_resolve_v4(&dns_, dnsName_, ips_, 4, &ipsResolved_, &completionEvent_);
    }

    virtual void handleCallback(const np_error_code ec)
    {
        BOOST_TEST(ec == NABTO_EC_OK);

        BOOST_TEST(ipsResolved_ == (size_t)1);

        // ipv4 addr: 1.2.3.4

        uint8_t ipv4[4] = {1,2,3,4};

        BOOST_TEST(ips_[0].type == NABTO_IPV4);

        BOOST_TEST(memcmp(ips_[0].ip.v4, ipv4, 4) == 0);
        testEnded();
    }

 private:
    const char* dnsName_ = "ip.test.dev.nabto.com";
};

class DnsTestV6 : public DnsTest {
 public:
    DnsTestV6(nabto::test::TestPlatform& tp)
        : DnsTest(tp)
    {
    }

    void start()
    {
        np_dns_async_resolve_v6(&dns_, dnsName_, ips_, 4, &ipsResolved_, &completionEvent_);
    }

    virtual void handleCallback(const np_error_code ec)
    {
        BOOST_TEST(ec == NABTO_EC_OK);

        BOOST_TEST(ipsResolved_ == (size_t)1);
        BOOST_TEST((int)ips_[0].type == (int)NABTO_IPV6);
        std::string resolvedIp(np_ip_address_to_string(&ips_[0]));

        // ipv6 addr: 2001:db8::1
        std::string targetV6 = "2001:0db8:0000:0000:0000:0000:0000:0001";
        std::string targetV6Mapped = "0000:0000:0000:0000:0000:ffff:0102:0304";

        // on some systems without internet facing ipv4 the ipv6 address is resolved as the ipv6 mapped ipv4 address
        if ((resolvedIp == targetV6) || (resolvedIp == targetV6Mapped)) {

        } else {
            BOOST_TEST(false, resolvedIp << "does not match the required ip");
        }
        testEnded();
    }

 private:
    const char* dnsName_ = "ip.test.dev.nabto.com";
};


class DnsTestNoSuchDomain : public DnsTest {
 public:
    DnsTestNoSuchDomain(nabto::test::TestPlatform& tp)
        : DnsTest(tp)
    {
    }

    void start()
    {
        np_dns_async_resolve_v4(&dns_, dnsName_, ips_, 4, &ipsResolved_, &completionEvent_);
    }

    virtual void handleCallback(const np_error_code ec)
    {
        if (ec != NABTO_EC_OK) {

        } else {
            BOOST_TEST(ipsResolved_ == (size_t)0);
        }
        testEnded();
    }

 private:
    const char* dnsName_ = "no-such-domain.dev.nabto.com";
};


}

BOOST_AUTO_TEST_SUITE(dns)

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))

BOOST_DATA_TEST_CASE(resolve_v4, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto tp = tpf->create();
    {
        DnsTestV4 dt(*tp);
        dt.start();

        dt.waitForTestEnd();
    }
}

BOOST_DATA_TEST_CASE(resolve_v6, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto tp = tpf->create();
    {
        DnsTestV6 dt(*tp);
        dt.start();
        dt.waitForTestEnd();
    }
}
BOOST_DATA_TEST_CASE(resolve_not_found, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto tp = tpf->create();
    {
        DnsTestNoSuchDomain dt(*tp);
        dt.start();
        dt.waitForTestEnd();
    }
}


BOOST_AUTO_TEST_SUITE_END()
