#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <api/nabto_device_defines.h>

#include <future>

namespace {

class AuthorizationDecider {
 public:

    AuthorizationDecider(NabtoDevice* device) {
        listener_ = nabto_device_listener_new(device);
        future_ = nabto_device_future_new(device);
        BOOST_TEST(nabto_device_authorization_request_init_listener(device, listener_) == NABTO_DEVICE_EC_OK);

        startListen();
    }

    ~AuthorizationDecider() {
        stop();
    }

    void stop()
    {
        nabto_device_listener_stop(listener_);
    }

    void startListen() {
        nabto_device_listener_new_authorization_request(listener_, future_, &authorizationRequest_);
        nabto_device_future_set_callback(future_, AuthorizationDecider::authorizationRequestCallback, this);
    }

    static void authorizationRequestCallback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        AuthorizationDecider* decider = (AuthorizationDecider*)userData;
        decider->handleCallback(ec);
    }

    void handleCallback(NabtoDeviceError ec)
    {
        if (ec == NABTO_DEVICE_EC_STOPPED) {
            nabto_device_listener_free(listener_);
            nabto_device_future_free(future_);
            return;
        }

        decide(authorizationRequest_);
        nabto_device_authorization_request_free(authorizationRequest_);

        startListen();
    }

    static void decide(NabtoDeviceAuthorizationRequest* authReq)
    {
        const char* action = nabto_device_authorization_request_get_action(authReq);
        std::string a(action);
        if (a == "Custom:AllowThis") {
            nabto_device_authorization_request_verdict(authReq, true);
        } else {
            nabto_device_authorization_request_verdict(authReq, false);
        }
    }

 private:

    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceAuthorizationRequest* authorizationRequest_;

};

class AuthCallback {
 public:

    AuthCallback()
    {

    }

    static void callback(bool verdict, void* userData, void*)
    {
        AuthCallback* cb = (AuthCallback*)userData;
        cb->ec_.set_value(verdict);
    }

    bool waitForCallback() {
        auto fut = ec_.get_future();
        return fut.get();
    }

 private:
    std::promise<bool> ec_;
};

}

BOOST_AUTO_TEST_SUITE(authorization)

BOOST_AUTO_TEST_CASE(allow_and_deny)
{
    NabtoDevice* device = nabto_device_new();

    {
        AuthorizationDecider authDecider(device);

        struct nabto_device_context* internalDevice = (struct nabto_device_context*)device;
        struct np_platform* pl = &internalDevice->pl;

        {
            AuthCallback authCallback;
            struct np_authorization_request* req = pl->authorization.create_request(pl, 0, "Custom:AllowThis");
            pl->authorization.check_access(req, &AuthCallback::callback, &authCallback, NULL);
            BOOST_TEST(authCallback.waitForCallback() == true);
        }
        {
            AuthCallback authCallback;
            struct np_authorization_request* req = pl->authorization.create_request(pl, 0, "Custom:DenyThis");
            pl->authorization.check_access(req, &AuthCallback::callback, &authCallback, NULL);
            BOOST_TEST(authCallback.waitForCallback() == false);
        }
    }

    nabto_device_stop(device);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_CASE(no_listener)
{
    NabtoDevice* device = nabto_device_new();

    {
        struct nabto_device_context* internalDevice = (struct nabto_device_context*)device;
        struct np_platform* pl = &internalDevice->pl;

        {
            AuthCallback authCallback;
            struct np_authorization_request* req = pl->authorization.create_request(pl, 0, "Custom:AllowThis");
            pl->authorization.check_access(req, &AuthCallback::callback, &authCallback, NULL);
            BOOST_TEST(authCallback.waitForCallback() == false);
        }
    }

    nabto_device_stop(device);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END()
