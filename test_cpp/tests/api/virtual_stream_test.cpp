#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_virtual.h>
#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>

#include <nlohmann/json.hpp>

#include <iostream>

namespace nabto {
namespace test {

class TestStreamDevice {
public:
    TestStreamDevice()
    {
        streamListener_ = NULL;
        newStreamFut_ = NULL;
        NabtoDeviceError ec;
        device_ = nabto_device_new();
        BOOST_TEST(device_);
        char* logLevel = getenv("NABTO_LOG_LEVEL");
        if (logLevel != NULL) {
            ec = nabto_device_set_log_std_out_callback(device_);
            ec = nabto_device_set_log_level(device_, logLevel);
        }

        ec = nabto_device_set_server_url(device_, "server.foo.bar");
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        char* key;
        nabto_device_create_private_key(device_, &key);
        ec = nabto_device_set_private_key(device_, key);
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        nabto_device_string_free(key);
        nabto_device_set_product_id(device_, "test");
        nabto_device_set_device_id(device_, "test");
        nabto_device_set_local_port(device_, 0);
        nabto_device_set_p2p_port(device_, 0);
        auto fut = nabto_device_future_new(device_);
        nabto_device_start(device_, fut);
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
    }

    ~TestStreamDevice()
    {
        if (connection_ != NULL) {
            // TODO: add close
            // nabto_device_virtual_connection_close(connection_)
            nabto_device_virtual_connection_free(connection_);
        }
        nabto_device_stop(device_);
        if (streamListener_ != NULL) {
            nabto_device_listener_free(streamListener_);
        }
        if (newStreamFut_ != NULL) {
            nabto_device_future_free(newStreamFut_);
        }
        nabto_device_free(device_);

    }

    NabtoDeviceVirtualConnection* makeConnection()
    {
        connection_ = nabto_device_virtual_connection_new(device_);
        return connection_;
    }

    NabtoDeviceVirtualConnection* makeConnection(const std::string& devFp, const std::string& cliFp)
    {
        makeConnection();
        nabto_device_virtual_connection_set_device_fingerprint(connection_, devFp.c_str());
        nabto_device_virtual_connection_set_client_fingerprint(connection_, cliFp.c_str());
        return connection_;
    }

    static void stream_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        TestStreamDevice* self = (TestStreamDevice*)data;
        self->onStream_(ec, self->stream_);
        self->stream_ = NULL;
        if (ec == NABTO_DEVICE_EC_OK) {
            nabto_device_listener_new_stream(self->streamListener_, self->newStreamFut_, &self->stream_);
            nabto_device_future_set_callback(self->newStreamFut_, &stream_callback, self);
        }
    }

    void streamListen(std::function<void(NabtoDeviceError ec, NabtoDeviceStream* stream)> onStream)
    {
        onStream_ = onStream;
        streamListener_ = nabto_device_listener_new(device_);
        newStreamFut_ = nabto_device_future_new(device_);
        BOOST_TEST(nabto_device_stream_init_listener_ephemeral(device_, streamListener_, &streamPort_) == NABTO_DEVICE_EC_OK);
        nabto_device_listener_new_stream(streamListener_, newStreamFut_, &stream_);
        nabto_device_future_set_callback(newStreamFut_, &stream_callback, this);

    }


    NabtoDevice* device_;
    NabtoDeviceVirtualConnection* connection_ = NULL;

    NabtoDeviceListener* streamListener_;
    NabtoDeviceFuture* newStreamFut_;
    std::function<void(NabtoDeviceError ec, NabtoDeviceStream* stream)> onStream_;
    NabtoDeviceStream* stream_;
    uint32_t streamPort_;

};

class TestStream {
public:
    TestStream(TestStreamDevice* device)
    {
        device_ = device;
    }

    ~TestStream()
    {
    }

    static void accepted_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        TestStream* self = (TestStream*)data;
        self->doRead();
    }

    void acceptStream(NabtoDeviceStream* stream)
    {
        stream_ = stream;
        future_ = nabto_device_future_new(device_->device_);
        nabto_device_stream_accept(stream_, future_);
        nabto_device_future_set_callback(future_, &accepted_callback, this);
    }

    static void read_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        TestStream* self = (TestStream*)data;
        if (ec == NABTO_DEVICE_EC_OK) {
            self->doWrite();
        }
        else {
            nabto_device_stream_free(self->stream_);
            nabto_device_future_free(self->future_);
        }
    }

    void doRead()
    {
        nabto_device_stream_read_some(stream_, future_, buffer_, 256, &readLen_);
        nabto_device_future_set_callback(future_, &read_callback, this);
    }

    static void write_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        TestStream* self = (TestStream*)data;
        if (ec == NABTO_DEVICE_EC_OK) {
            self->doRead();
        }
        else {
            nabto_device_stream_free(self->stream_);
            nabto_device_future_free(self->future_);
        }
    }

    void doWrite()
    {
        nabto_device_stream_write(stream_, future_, buffer_, readLen_);
        nabto_device_future_set_callback(future_, &read_callback, this);

    }

    TestStreamDevice* device_;
    NabtoDeviceStream* stream_ = NULL;
    NabtoDeviceFuture* future_;
    uint8_t buffer_[256];
    size_t readLen_;

};


}
} // namespace

BOOST_AUTO_TEST_SUITE(virtual_stream)

BOOST_AUTO_TEST_CASE(open_stream)
{
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
        });


    NabtoDeviceVirtualConnection* conn = td.makeConnection();
    NabtoDeviceVirtualStream* virStream = nabto_device_virtual_stream_new(conn);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_open(virStream, fut, td.streamPort_);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);

    nabto_device_virtual_stream_abort(virStream);
    nabto_device_virtual_stream_free(virStream);
}


BOOST_AUTO_TEST_CASE(write_stream)
{
    const char* writeBuffer = "Hello world";
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });


    NabtoDeviceVirtualConnection* conn = td.makeConnection();
    NabtoDeviceVirtualStream* virStream = nabto_device_virtual_stream_new(conn);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_open(virStream, fut, td.streamPort_);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    nabto_device_virtual_stream_write(virStream, fut, writeBuffer, strlen(writeBuffer));
    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(fut);
    nabto_device_virtual_stream_abort(virStream);
    nabto_device_virtual_stream_free(virStream);
}

BOOST_AUTO_TEST_CASE(write_read_stream)
{
    const char* writeBuffer = "Hello world";
    char readBuffer[256];
    memset(readBuffer, 0, 256);
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        std::cout << "Got stream listen callback with ec: " << nabto_device_error_get_string(ec) << std::endl;
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
        });


    NabtoDeviceVirtualConnection* conn = td.makeConnection();
    NabtoDeviceVirtualStream* virStream = nabto_device_virtual_stream_new(conn);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_open(virStream, fut, td.streamPort_);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    std::cout << "open future resolved" << std::endl;

    nabto_device_virtual_stream_write(virStream, fut, writeBuffer, strlen(writeBuffer));
    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    std::cout << "stream write future resolved" << std::endl;

    size_t readen = 0;
    nabto_device_virtual_stream_read_all(virStream, fut, readBuffer, strlen(writeBuffer), &readen);
    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    std::cout << "stream read all future resolved" << std::endl;

    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    nabto_device_future_free(fut);
    nabto_device_virtual_stream_abort(virStream);
    nabto_device_virtual_stream_free(virStream);
}



BOOST_AUTO_TEST_SUITE_END()
