#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <test_platform.hpp>

#include <platform/np_error_code.h>
#include <platform/np_platform.h>
#include <platform/np_ip_address.h>
#include <platform/np_completion_event.h>

#ifdef HAVE_LIBEVENT
#include <test_platform_libevent.hpp>
#endif

namespace {

class DnsTest {
 public:
    DnsTest(nabto::test::TestPlatform& tp)
        : tp_(tp), pl_(tp.getPlatform())
    {
        pl_->dns.create_resolver(pl_, &resolver_);
        np_completion_event_init(pl_, &completionEvent_, &DnsTest::dnsCallback, this);
    }
    static void dnsCallback(const np_error_code ec, void* data)
    {
        DnsTest* t = (DnsTest*)data;
        t->handleCallback(ec);
    }

    virtual void handleCallback(const np_error_code ec) = 0;
 protected:
    nabto::test::TestPlatform& tp_;
    struct np_platform* pl_;
    struct np_dns_resolver* resolver_;
    struct np_ip_address ips_[4];
    size_t ipsResolved_;
    struct np_completion_event completionEvent_;
};


class DnsTestV4 : public DnsTest {
 public:
    DnsTestV4(nabto::test::TestPlatform& tp)
        : DnsTest(tp)
    {
    }

    void start()
    {
        pl_->dns.async_resolve_v4(resolver_, dnsName_, ips_, 4, &ipsResolved_, &completionEvent_);
        tp_.run();
    }

    virtual void handleCallback(const np_error_code ec)
    {
        BOOST_TEST(ec == NABTO_EC_OK);

        BOOST_TEST(ipsResolved_ == (size_t)1);

        // ipv4 addr: 1.2.3.4

        uint8_t ipv4[4] = {1,2,3,4};

        BOOST_TEST(ips_[0].type == NABTO_IPV4);

        BOOST_TEST(memcmp(ips_[0].ip.v4, ipv4, 4) == 0);
        end();
    }

    void end() {
        pl_->dns.destroy_resolver(resolver_);
        tp_.stop();
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
        pl_->dns.async_resolve_v6(resolver_, dnsName_, ips_, 4, &ipsResolved_, &completionEvent_);
        tp_.run();
    }

    virtual void handleCallback(const np_error_code ec)
    {
        BOOST_TEST(ec == NABTO_EC_OK);

        BOOST_TEST(ipsResolved_ == (size_t)1);
        // ipv6 addr: 2001:db8::1
        uint8_t ipv6[16] = {0x20, 0x01, 0x0d, 0xb8,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x01 };

        BOOST_TEST(ips_[0].type == NABTO_IPV6);
        BOOST_TEST(memcmp(ips_[0].ip.v6, ipv6, 16) == 0);

        end();
    }

    void end() {
        pl_->dns.destroy_resolver(resolver_);
        tp_.stop();
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
        pl_->dns.async_resolve_v4(resolver_, dnsName_, ips_, 4, &ipsResolved_, &completionEvent_);
        tp_.run();
    }

    virtual void handleCallback(const np_error_code ec)
    {
        if (ec != NABTO_EC_OK) {

        } else {
            BOOST_TEST(ipsResolved_ == (size_t)0);
        }

        end();
    }

    void end() {
        pl_->dns.destroy_resolver(resolver_);
        tp_.stop();
    }

 private:
    const char* dnsName_ = "no-such-domain.dev.nabto.com";
};


}

BOOST_AUTO_TEST_SUITE(dns)

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))

BOOST_DATA_TEST_CASE(resolve_v4, nabto::test::TestPlatform::multi(), tp)
{
    {
        DnsTestV4 dt(*tp);
        dt.start();
    }
}

BOOST_DATA_TEST_CASE(resolve_v6, nabto::test::TestPlatform::multi(), tp)
{
    {
        DnsTestV6 dt(*tp);
        dt.start();
    }
}
BOOST_DATA_TEST_CASE(resolve_not_found, nabto::test::TestPlatform::multi(), tp)
{
    {
        DnsTestNoSuchDomain dt(*tp);
        dt.start();
    }
}


BOOST_AUTO_TEST_SUITE_END()
