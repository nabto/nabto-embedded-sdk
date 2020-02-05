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
        nabto_device_future_free(future_);
        nabto_device_listener_free(listener_);
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
            nabto_device_authorization_request_allow(authReq);
        } else {
            nabto_device_authorization_request_deny(authReq);
        }
    }

 private:

    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceAuthorizationRequest* authorizationRequest_;

};

class AuthCallback {
 public:

    AuthCallback(struct np_platform* pl)
        : pl_(pl)
    {

    }

    static void callback(struct np_authorization_request* authorizationRequest, const np_error_code ec, void* userData)
    {
        AuthCallback* cb = (AuthCallback*)userData;
        cb->ec_.set_value(ec);
        cb->pl_->authorization.free_request(authorizationRequest);
    }

    NabtoDeviceError waitForCallback() {
        auto fut = ec_.get_future();
        return fut.get();
    }

 private:
    std::promise<np_error_code> ec_;
    struct np_platform* pl_;
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
            AuthCallback authCallback(pl);
            struct np_authorization_request* req = pl->authorization.create_request(pl, 0, "Custom:AllowThis");
            pl->authorization.check_access(req, &AuthCallback::callback, &authCallback);
            BOOST_TEST(authCallback.waitForCallback() == NABTO_DEVICE_EC_OK);
        }
        {
            AuthCallback authCallback(pl);
            struct np_authorization_request* req = pl->authorization.create_request(pl, 0, "Custom:DenyThis");
            pl->authorization.check_access(req, &AuthCallback::callback, &authCallback);
            BOOST_TEST(authCallback.waitForCallback() == NABTO_DEVICE_EC_ACCESS_DENIED);
        }
    }

    nabto_device_stop(device);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END()
