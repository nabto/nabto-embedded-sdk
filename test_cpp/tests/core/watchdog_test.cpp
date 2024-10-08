#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>
#include <test_platform_libevent.hpp>

#include <core/nc_attacher_watchdog.h>
#include <core/nc_attacher.h>
#include <core/nc_device.h>

#include <future>
#include <thread>
#include <chrono>

namespace nabto {
namespace test {

static uint32_t ts_now_ms(struct np_timestamp* obj);

static struct np_timestamp_functions module;

uint32_t ts_now_ms(struct np_timestamp* obj)
{
    uint32_t* time = (uint32_t*)obj->data;
    return *time;
}

class WatchdogTest {
  public:
    WatchdogTest() {
        module.now_ms = &ts_now_ms;
        struct np_timestamp obj;
        obj.mptr = &module;
        obj.data = &time_;
        tp_ = std::unique_ptr<nabto::test::TestPlatform>(new nabto::test::TestPlatformLibevent(obj));
        struct np_platform* pl = tp_->getPlatform();

        nc_coap_client_init(tp_->getPlatform(), &coapClient_);

        nc_attacher_init(&attach_, tp_->getPlatform(), &device_, &coapClient_, NULL, NULL);

        np_error_code ec = nc_attacher_watchdog_init(&ctx_, pl, &attach_, &watchDogCallback, this);
        BOOST_TEST(ec == NABTO_EC_OK);
    }

    ~WatchdogTest() {
        nc_attacher_watchdog_deinit(&ctx_);
        nc_coap_client_stop(&coapClient_);
        tp_->stop();
        nc_attacher_deinit(&attach_);
        nc_coap_client_deinit(&coapClient_);
    }

    static void watchDogCallback(enum nc_device_event event, void* data) {
        nabto::test::WatchdogTest* self = (nabto::test::WatchdogTest*)data;
        self->lastEvent_ = event;
        self->wasWatchdogCalled_ = true;
        self->watchdogCalled_.set_value();
    }

    struct nc_watchdog_ctx* getWatchdogCtx() {
        return &ctx_;
    }

    enum nc_device_event getLastEvent() {
        return lastEvent_;
    }

    void waitForCallback() {
        std::future<void> fut = watchdogCalled_.get_future();
        fut.get();
    }

    void setAttacherState(enum nc_attacher_attach_state state)
    {
        nc_attacher_watchdog_state_changed(state, &ctx_);
    }

    bool wasWatchdogCalled()
    {
        return wasWatchdogCalled_;
    }

    void addTime(uint32_t time) {
        time_ += time;
    }

  private:
    struct nc_attach_context attach_;
    struct nc_device_context device_;
    struct nc_coap_client_context coapClient_;
    struct nc_watchdog_ctx ctx_;
    std::unique_ptr<nabto::test::TestPlatform> tp_;
    bool wasWatchdogCalled_ = false;
    enum nc_device_event lastEvent_ = NC_DEVICE_EVENT_ATTACHED;
    std::promise<void> watchdogCalled_;
    uint32_t time_ = 0;

};
}
}

BOOST_AUTO_TEST_SUITE(watchdog)

#if defined(HAVE_LIBEVENT)

BOOST_AUTO_TEST_CASE(watchdog_trigger, *boost::unit_test::timeout(300))
{
    nabto::test::WatchdogTest test;
    nc_attacher_watchdog_set_timeout(test.getWatchdogCtx(), 50);
    test.setAttacherState(NC_ATTACHER_STATE_DNS);
    test.addTime(51);
    test.waitForCallback();
    BOOST_TEST(test.getLastEvent() == NC_DEVICE_EVENT_WATCHDOG_FAILURE);

}

BOOST_AUTO_TEST_CASE(watchdog_dont_trigger, *boost::unit_test::timeout(300))
{
    nabto::test::WatchdogTest test;
    nc_attacher_watchdog_set_timeout(test.getWatchdogCtx(), 50);
    test.setAttacherState(NC_ATTACHER_STATE_DNS);
    test.addTime(40);
    test.setAttacherState(NC_ATTACHER_STATE_DNS);
    test.addTime(40);
    test.setAttacherState(NC_ATTACHER_STATE_DNS);
    test.addTime(40);
    test.setAttacherState(NC_ATTACHER_STATE_DNS);

    BOOST_TEST(!test.wasWatchdogCalled());
}
#endif

BOOST_AUTO_TEST_SUITE_END()
