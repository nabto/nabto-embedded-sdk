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
        (void)fut;
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
    TestStream(TestStreamDevice* device)
    {
        device_ = device;
        future_ = nabto_device_future_new(device_->device_);
        buffer_ = (uint8_t*)calloc(1, 256);
        bufferLen_ = 256;

    }

    TestStream(TestStreamDevice* device, size_t readBufferSize)
    {
        device_ = device;
        future_ = nabto_device_future_new(device_->device_);
        buffer_ = (uint8_t*)calloc(1, readBufferSize);
        bufferLen_ = readBufferSize;
    }

    ~TestStream()
    {
        if (stream_ != NULL) {
            nabto_device_stream_free(stream_);
        }
        nabto_device_future_free(future_);
        free(buffer_);
    }

    void acceptStream(NabtoDeviceStream* stream)
    {
        stream_ = stream;
        nabto_device_stream_accept(stream_, future_);
    }

    void doRead()
    {
        nabto_device_stream_read_some(stream_, future_, buffer_, bufferLen_, &readLen_);
    }

    void futureWait(NabtoDeviceError expect) {
        NabtoDeviceError ec = nabto_device_future_wait(future_);
        BOOST_TEST(ec == expect);
    }

    void doWrite()
    {
        nabto_device_stream_write(stream_, future_, buffer_, readLen_);
    }

    void close()
    {
        nabto_device_stream_close(stream_, future_);
    }

    TestStreamDevice* device_;
    NabtoDeviceStream* stream_ = NULL;
    NabtoDeviceFuture* future_;
    uint8_t* buffer_;
    size_t bufferLen_;

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

    ts.futureWait(NABTO_DEVICE_EC_OK);

    ts.doRead();

    nabto_device_virtual_stream_abort(virStream);
    ts.futureWait(NABTO_DEVICE_EC_ABORTED);
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();
    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));
    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));
    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read

    ts.doWrite();
    size_t readen = td.virtualStreamReadAll(readBuffer, strlen(writeBuffer));
    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for write
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read
    ts.doWrite();

    size_t readen = td.virtualStreamReadAll(readBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for write
    ts.doRead();
    BOOST_TEST(readen == strlen(writeBuffer));

    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    memset(readBuffer, 0, 256);
    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read
    ts.doWrite();

    readen = td.virtualStreamReadAll(readBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for write
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

    td.makeConnection();
    NabtoDeviceVirtualStream* virtStream = td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    auto fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_close(virtStream, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    ts.futureWait(NABTO_DEVICE_EC_EOF); // wait for read

    nabto_device_future_free(fut);
}

BOOST_AUTO_TEST_CASE(close_while_write_stream)
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    auto fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_write(virtStream, fut, writeBuffer, strlen(writeBuffer));

    auto fut2 = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_close(virtStream, fut2);

    ts.doRead();

    NabtoDeviceError ec;
    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    ec = nabto_device_future_wait(fut2);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read

    ts.doRead();
    ts.futureWait(NABTO_DEVICE_EC_EOF); // wait for read

    nabto_device_future_free(fut);
    nabto_device_future_free(fut2);

}

BOOST_AUTO_TEST_CASE(write_with_multiple_read_some)
{
    const char* writeBuffer = "Hello world";
    char readBuffer[256];
    memset(readBuffer, 0, 256);
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td, 6);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });


    td.makeConnection();
    NabtoDeviceVirtualStream* virtStream = td.virtualStreamOpen();

    // read stream 6B
    // Write to virtual stream 11B
    // wait for read stream
    // write stream 6B
    // virtual read 6B
    // wait for write stream + virtual read
    // read stream 5B
    // wait for read stream
    // write stream 5B
    // virtual read 5B
    // wait for virtual read
    // wait for write stream
    // wait for virtual write 11B


    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_write(td.virtStream_, fut, writeBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read
    ts.doWrite();

    size_t readen = td.virtualStreamReadSome(readBuffer, 256);
    BOOST_TEST((readen == 6));
    char* ptr = readBuffer + readen;

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for write

    ts.doRead();
    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read
    ts.doWrite();

    readen = td.virtualStreamReadSome(ptr, 256);
    BOOST_TEST(readen == strlen(writeBuffer) - 6);

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for write

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);


    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    nabto_device_virtual_stream_abort(virtStream);
    nabto_device_future_free(fut);
}

BOOST_AUTO_TEST_CASE(close_from_server_stream)
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    size_t readen = 0;
    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    NabtoDeviceFuture* fut2 = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_write(virtStream, fut, writeBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read

    nabto_device_virtual_stream_read_all(virtStream, fut2, readBuffer, strlen(writeBuffer), &readen);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    ts.close();

    ec = nabto_device_future_wait(fut2);
    BOOST_TEST((readen == 0));
    BOOST_TEST(ec == NABTO_DEVICE_EC_EOF);

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for close

    nabto_device_future_free(fut);
    nabto_device_future_free(fut2);

    nabto_device_virtual_stream_abort(virtStream);
}

BOOST_AUTO_TEST_CASE(multiple_read_all_with_one_write)
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read
    ts.doWrite();

    size_t readen = td.virtualStreamReadAll(readBuffer, 6);
    BOOST_TEST((readen == 6));

    readen = td.virtualStreamReadAll(readBuffer+6, strlen(writeBuffer)-6);
    BOOST_TEST(readen == strlen(writeBuffer)-6);

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for write

    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    nabto_device_virtual_stream_abort(virtStream);
}

BOOST_AUTO_TEST_CASE(multiple_read_some_with_one_write)
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read
    ts.doWrite();

    size_t readen = td.virtualStreamReadSome(readBuffer, 6);
    BOOST_TEST((readen == 6));

    readen = td.virtualStreamReadSome(readBuffer + 6, strlen(writeBuffer) - 6);
    BOOST_TEST(readen == strlen(writeBuffer) - 6);

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for write

    BOOST_TEST(strcmp(readBuffer, writeBuffer) == 0);

    nabto_device_virtual_stream_abort(virtStream);

}

BOOST_AUTO_TEST_CASE(abort_while_writing)
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_write(td.virtStream_, fut, writeBuffer, strlen(writeBuffer));
    nabto_device_virtual_stream_abort(virtStream);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST((ec == NABTO_DEVICE_EC_ABORTED));
    nabto_device_future_free(fut);
}

BOOST_AUTO_TEST_CASE(abort_while_reading)
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

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    td.virtualStreamWrite(writeBuffer, strlen(writeBuffer));

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for read

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    size_t readen = 0;
    nabto_device_virtual_stream_read_all(td.virtStream_, fut, readBuffer, strlen(writeBuffer), &readen);
    nabto_device_virtual_stream_abort(virtStream);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST((ec == NABTO_DEVICE_EC_ABORTED));
    nabto_device_future_free(fut);
}

BOOST_AUTO_TEST_SUITE_END()
