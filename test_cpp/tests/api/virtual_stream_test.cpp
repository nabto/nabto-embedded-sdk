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
        if (virtStream_ != NULL) {
            nabto_device_virtual_stream_free(virtStream_);
        }
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

    NabtoDeviceVirtualStream* virtualStreamOpen()
    {
        virtStream_ = nabto_device_virtual_stream_new(connection_);
        NabtoDeviceFuture* fut = nabto_device_future_new(device_);
        nabto_device_virtual_stream_open(virtStream_, fut, streamPort_);
        NabtoDeviceError ec = nabto_device_future_wait(fut);
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        nabto_device_future_free(fut);
        return virtStream_;
    }

    void virtualStreamWrite(const void* buffer, size_t len)
    {
        NabtoDeviceFuture* fut = nabto_device_future_new(device_);
        nabto_device_virtual_stream_write(virtStream_, fut, buffer, len);
        NabtoDeviceError ec = nabto_device_future_wait(fut);
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        nabto_device_future_free(fut);
    }

    size_t virtualStreamReadAll(void* buffer, size_t len)
    {
        size_t readen = 0;
        NabtoDeviceFuture* fut = nabto_device_future_new(device_);
        nabto_device_virtual_stream_read_all(virtStream_, fut, buffer, len, &readen);
        NabtoDeviceError ec = nabto_device_future_wait(fut);
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        nabto_device_future_free(fut);
        return readen;
    }

    size_t virtualStreamReadSome(void* buffer, size_t len)
    {
        size_t readen = 0;
        NabtoDeviceFuture* fut = nabto_device_future_new(device_);
        nabto_device_virtual_stream_read_some(virtStream_, fut, buffer, len, &readen);
        NabtoDeviceError ec = nabto_device_future_wait(fut);
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        nabto_device_future_free(fut);
        return readen;
    }

    NabtoDevice* device_;
    NabtoDeviceVirtualConnection* connection_ = NULL;

    NabtoDeviceListener* streamListener_;
    NabtoDeviceFuture* newStreamFut_;
    std::function<void(NabtoDeviceError ec, NabtoDeviceStream* stream)> onStream_;
    NabtoDeviceStream* stream_;
    uint32_t streamPort_;

    NabtoDeviceVirtualStream* virtStream_ = NULL;

};

class TestStream {
public:
    enum EventType {
        ACCEPT_CALLBACK,
        READ_CALLBACK,
        WRITE_CALLBACK
    };

    TestStream(TestStreamDevice* device)
    {
        device_ = device;
        future_ = nabto_device_future_new(device_->device_);

    }

    ~TestStream()
    {
        if (stream_ != NULL) {
            nabto_device_stream_abort(stream_);
        }
    }

    static void accepted_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        TestStream* self = (TestStream*)data;
        if(self->evCb_) {
            self->evCb_(ACCEPT_CALLBACK, ec);
        }
        if (!self->noRead_) {
            self->doRead();
        }
    }

    void acceptStream(NabtoDeviceStream* stream)
    {
        stream_ = stream;
        nabto_device_stream_accept(stream_, future_);
        nabto_device_future_set_callback(future_, &accepted_callback, this);
    }

    void acceptNoReadStream(NabtoDeviceStream* stream)
    {
        stream_ = stream;
        noRead_ = true;
        nabto_device_stream_accept(stream_, future_);
        nabto_device_future_set_callback(future_, &accepted_callback, this);
    }

    static void read_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        TestStream* self = (TestStream*)data;
        if (self->evCb_) {
            self->evCb_(READ_CALLBACK, ec);
        }
        if (ec == NABTO_DEVICE_EC_OK) {
            self->doWrite();
        } else {
            auto s = self->stream_;
            self->stream_ = NULL;
            nabto_device_stream_free(s);
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
        if (self->evCb_) {
            self->evCb_(WRITE_CALLBACK, ec);
        }
        if (ec == NABTO_DEVICE_EC_OK) {
            self->doRead();
        } else {
            auto s = self->stream_;
            self->stream_ = NULL;
            nabto_device_stream_free(s);
            nabto_device_future_free(self->future_);
        }

    }

    void doWrite()
    {
        nabto_device_stream_write(stream_, future_, buffer_, readLen_);
        nabto_device_future_set_callback(future_, &write_callback, this);

    }

    void setEventCallback(std::function<void (enum EventType ev, NabtoDeviceError ec)> cb) {
        evCb_ = cb;
    }

    TestStreamDevice* device_;
    NabtoDeviceStream* stream_ = NULL;
    NabtoDeviceFuture* future_;
    uint8_t buffer_[256];
    size_t readLen_;
    std::function<void(enum EventType ev, NabtoDeviceError ec)> evCb_;
    bool noRead_ = false;

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


    td.makeConnection();
    NabtoDeviceVirtualStream* virtStream = td.virtualStreamOpen();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    nabto_device_virtual_stream_abort(virtStream);
}

BOOST_AUTO_TEST_CASE(write_read_stream)
{
    const char* writeBuffer = "Hello world";
    char readBuffer[256];
    memset(readBuffer, 0, 256);
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
        });


    td.makeConnection();
    NabtoDeviceVirtualStream* virtStream = td.virtualStreamOpen();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    size_t readen = td.virtualStreamReadAll(readBuffer, strlen(writeBuffer));
    BOOST_TEST(readen == strlen(writeBuffer));

    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    nabto_device_virtual_stream_abort(virtStream);
}

BOOST_AUTO_TEST_CASE(multi_write_read_stream)
{
    const char* writeBuffer = "Hello world";
    char readBuffer[256];
    memset(readBuffer, 0, 256);
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
        });


    td.makeConnection();

    NabtoDeviceVirtualStream* virtStream = td.virtualStreamOpen();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    size_t readen = td.virtualStreamReadAll(readBuffer, strlen(writeBuffer));
    BOOST_TEST(readen == strlen(writeBuffer));

    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    memset(readBuffer, 0, 256);
    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    readen = td.virtualStreamReadAll(readBuffer, strlen(writeBuffer));
    BOOST_TEST(readen == strlen(writeBuffer));

    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    nabto_device_virtual_stream_abort(virtStream);
}

BOOST_AUTO_TEST_CASE(close_stream)
{
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
        });

    ts.setEventCallback([&](nabto::test::TestStream::EventType ev, NabtoDeviceError ec) {
        switch (ev) {
            case nabto::test::TestStream::EventType::ACCEPT_CALLBACK:
                BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
                break;
            case nabto::test::TestStream::EventType::READ_CALLBACK:
                BOOST_TEST(ec == NABTO_DEVICE_EC_EOF);
                break;
            default:
                // We do not expect write events
                std::cout << "Unexpected event type: " << ev << std::endl;
                BOOST_TEST(false);
                break;
        }
    });

    td.makeConnection();
    NabtoDeviceVirtualStream* virtStream = td.virtualStreamOpen();

    auto fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_close(virtStream, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);
}

BOOST_AUTO_TEST_CASE(close_while_write_stream)
{
    const char* writeBuffer = "Hello world";
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    size_t readCount = 0;

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptNoReadStream(stream);
        }
        });

    ts.setEventCallback([&](nabto::test::TestStream::EventType ev, NabtoDeviceError ec) {
        switch (ev) {
        case nabto::test::TestStream::EventType::ACCEPT_CALLBACK:
            BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
            break;
        case nabto::test::TestStream::EventType::READ_CALLBACK:
        readCount++;
        if (readCount == 1) {
            BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
            std::cout << "Read ec: " << nabto_device_error_get_message(ec) << std::endl;
        }
        if (readCount == 2) {
            BOOST_TEST(ec == NABTO_DEVICE_EC_EOF);
        }
            break;
        default:
            break;
        }
        });

    td.makeConnection();
    NabtoDeviceVirtualStream* virtStream = td.virtualStreamOpen();

    auto fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_write(virtStream, fut, writeBuffer, strlen(writeBuffer));

    auto fut2 = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_close(virtStream, fut2);

    NabtoDeviceError ec = nabto_device_future_timed_wait(fut, 50);
    BOOST_TEST(ec == NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED);

    ts.doRead();
    std::cout << "Start wait for write" << std::endl;

    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    std::cout << "Start wait for close" << std::endl;
    ec = nabto_device_future_wait(fut2);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    std::cout << "Done waiting" << std::endl;


    nabto_device_future_free(fut);
    nabto_device_future_free(fut2);

}
}



BOOST_AUTO_TEST_SUITE_END()
