#include <boost/test/unit_test.hpp>

#include <util/live_allocations.hpp>

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

BOOST_AUTO_TEST_CASE(read_after_abort, *boost::unit_test::timeout(60))
{
    // A read started after the stream was aborted was stored and never
    // resolved, which also held the stream until nabto_device_stop gave up
    // waiting for it.
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);
    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });
    td.makeConnection();
    NabtoDeviceVirtualStream* virStream = td.virtualStreamOpen();
    ts.futureWait(NABTO_DEVICE_EC_OK);

    nabto_device_virtual_stream_abort(virStream);

    char buffer[16];
    size_t readLength = 0;
    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_read_some(virStream, fut, buffer, sizeof(buffer), &readLength);
    BOOST_TEST(nabto_device_future_timed_wait(fut, 2000) == NABTO_DEVICE_EC_ABORTED);
    nabto_device_virtual_stream_read_all(virStream, fut, buffer, sizeof(buffer), &readLength);
    BOOST_TEST(nabto_device_future_timed_wait(fut, 2000) == NABTO_DEVICE_EC_ABORTED);
    nabto_device_future_free(fut);
}

BOOST_AUTO_TEST_CASE(read_all_while_reading, *boost::unit_test::timeout(60))
{
    char readBuffer[256];
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
    NabtoDeviceFuture* fut2 = nabto_device_future_new(td.device_);
    size_t readen = 0;
    size_t readen2 = 0;
    nabto_device_virtual_stream_read_all(virtStream, fut, readBuffer, sizeof(readBuffer), &readen);
    nabto_device_virtual_stream_read_all(virtStream, fut2, readBuffer, sizeof(readBuffer), &readen2);
    BOOST_TEST((nabto_device_future_wait(fut2) == NABTO_DEVICE_EC_OPERATION_IN_PROGRESS));

    // The rejected read must leave the device usable.
    nabto_device_virtual_stream_abort(virtStream);
    BOOST_TEST((nabto_device_future_wait(fut) == NABTO_DEVICE_EC_ABORTED));
    nabto_device_future_free(fut);
    nabto_device_future_free(fut2);
}

BOOST_AUTO_TEST_CASE(close_twice_while_closing, *boost::unit_test::timeout(60))
{
    // A second close while the first is outstanding must be rejected
    // without disturbing the first close.
    const char* writeBuffer = "Hello world";
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    // The client does not read, so the server write stays outstanding and
    // the first close waits for it.
    NabtoDeviceFuture* writeFut = nabto_device_future_new(td.device_);
    nabto_device_stream_write(ts.stream_, writeFut, writeBuffer, strlen(writeBuffer));

    NabtoDeviceFuture* closeFut1 = nabto_device_future_new(td.device_);
    NabtoDeviceFuture* closeFut2 = nabto_device_future_new(td.device_);
    nabto_device_stream_close(ts.stream_, closeFut1);
    nabto_device_stream_close(ts.stream_, closeFut2);
    BOOST_TEST(nabto_device_future_wait(closeFut2) == NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);

    // The first close is still outstanding and is resolved by the abort.
    nabto_device_stream_abort(ts.stream_);
    BOOST_TEST(nabto_device_future_wait(writeFut) == NABTO_DEVICE_EC_ABORTED);
    BOOST_TEST(nabto_device_future_wait(closeFut1) == NABTO_DEVICE_EC_ABORTED);

    nabto_device_future_free(writeFut);
    nabto_device_future_free(closeFut1);
    nabto_device_future_free(closeFut2);
}

BOOST_AUTO_TEST_CASE(open_stream_no_listener, *boost::unit_test::timeout(60))
{
    // Opening a virtual stream on a port without a listener must fail
    // without touching freed memory, and the stream must be freeable.
    nabto::test::TestStreamDevice td;

    NabtoDeviceVirtualConnection* conn = td.makeConnection();
    NabtoDeviceVirtualStream* virStream = nabto_device_virtual_stream_new(conn);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_open(virStream, fut, 4242);
    NabtoDeviceError ec = nabto_device_future_timed_wait(fut, 5000);
    BOOST_TEST(ec == NABTO_DEVICE_EC_STOPPED);
    nabto_device_future_free(fut);

    nabto_device_virtual_stream_free(virStream);
}

BOOST_AUTO_TEST_CASE(open_stream_server_frees_without_accept, *boost::unit_test::timeout(60))
{
    // If the application frees the new stream without accepting it, the
    // virtual stream open future resolves with STOPPED.
    nabto::test::TestStreamDevice td;

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            nabto_device_stream_free(stream);
        }
    });

    NabtoDeviceVirtualConnection* conn = td.makeConnection();
    NabtoDeviceVirtualStream* virStream = nabto_device_virtual_stream_new(conn);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_open(virStream, fut, td.streamPort_);
    NabtoDeviceError ec = nabto_device_future_timed_wait(fut, 5000);
    BOOST_TEST(ec == NABTO_DEVICE_EC_STOPPED);
    if (ec == NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED) {
        // avoid freeing a future the device still references
        nabto_device_virtual_stream_abort(virStream);
        nabto_device_future_wait(fut);
    }
    nabto_device_future_free(fut);

    nabto_device_virtual_stream_free(virStream);
}

BOOST_AUTO_TEST_CASE(free_stream_while_reading, *boost::unit_test::timeout(60))
{
    // Freeing a stream with an outstanding read must not leave a pending
    // completion event pointing into the freed stream.
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.doRead();

    nabto_device_stream_free(ts.stream_);
    ts.stream_ = NULL;
    ts.futureWait(NABTO_DEVICE_EC_ABORTED);
}

BOOST_AUTO_TEST_CASE(free_stream_while_writing_and_closing, *boost::unit_test::timeout(60))
{
    // The virtual client does not read, so the write stays outstanding and
    // the close waits for it. Freeing the stream aborts both.
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept
    ts.readLen_ = 10;
    ts.doWrite();

    NabtoDeviceFuture* closeFut = nabto_device_future_new(td.device_);
    nabto_device_stream_close(ts.stream_, closeFut);

    nabto_device_stream_free(ts.stream_);
    ts.stream_ = NULL;
    ts.futureWait(NABTO_DEVICE_EC_ABORTED);
    BOOST_TEST(nabto_device_future_wait(closeFut) == NABTO_DEVICE_EC_ABORTED);
    nabto_device_future_free(closeFut);
}

BOOST_AUTO_TEST_CASE(free_virtual_stream_while_reading, *boost::unit_test::timeout(60))
{
    // The virtual client frees its stream with an outstanding read while
    // the application still holds the stream. The read is aborted, and the
    // application can still use and free its end of the stream.
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    NabtoDeviceVirtualStream* virStream = td.virtualStreamOpen();
    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    uint8_t buffer[10];
    size_t readen = 0;
    NabtoDeviceFuture* readFut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_read_some(virStream, readFut, buffer, sizeof(buffer), &readen);

    nabto_device_virtual_stream_free(virStream);
    td.virtStream_ = NULL;
    BOOST_TEST(nabto_device_future_wait(readFut) == NABTO_DEVICE_EC_ABORTED);
    nabto_device_future_free(readFut);

    // The application's write fails as the client side is gone.
    ts.readLen_ = 10;
    ts.doWrite();
    NabtoDeviceError ec = nabto_device_future_wait(ts.future_);
    BOOST_TEST(ec != NABTO_DEVICE_EC_OK);
}

BOOST_AUTO_TEST_CASE(free_device_after_freeing_streams_with_outstanding_operations, *boost::unit_test::timeout(60))
{
    // Freeing the streams leaves their outstanding operations for the device
    // to complete. Stopping and freeing the device right after must neither
    // use freed memory nor leak.
    nabto::test::LiveAllocations allocations;
    {
        nabto::test::TestStreamDevice td;
        {
            nabto::test::TestStream ts(&td);
            td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
                if (ec == NABTO_DEVICE_EC_OK) {
                    ts.acceptStream(stream);
                }
            });
            td.makeConnection();
            NabtoDeviceVirtualStream* virStream = td.virtualStreamOpen();
            ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

            ts.doRead();
            uint8_t buffer[10];
            size_t readen = 0;
            NabtoDeviceFuture* readFut = nabto_device_future_new(td.device_);
            nabto_device_virtual_stream_read_some(virStream, readFut, buffer, sizeof(buffer), &readen);

            nabto_device_stream_free(ts.stream_);
            ts.stream_ = NULL;
            nabto_device_virtual_stream_free(virStream);
            td.virtStream_ = NULL;

            ts.futureWait(NABTO_DEVICE_EC_ABORTED);
            BOOST_TEST(nabto_device_future_wait(readFut) == NABTO_DEVICE_EC_ABORTED);
            nabto_device_future_free(readFut);
        }
        // Frees the virtual connection, stops and frees the device.
    }
    BOOST_TEST(allocations.live() == 0u);
}

BOOST_AUTO_TEST_CASE(operations_after_failed_open, *boost::unit_test::timeout(60))
{
    // When opening fails, e.g. because the stream limit is reached, the
    // virtual stream has no core stream. Operations on it passed NULL to the
    // core.
    nabto::test::TestStreamDevice td;
    BOOST_TEST(nabto_device_limit_streams(td.device_, 0) == NABTO_DEVICE_EC_OK);

    NabtoDeviceVirtualConnection* conn = td.makeConnection();
    NabtoDeviceVirtualStream* virStream = nabto_device_virtual_stream_new(conn);
    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);

    nabto_device_virtual_stream_open(virStream, fut, 4242);
    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OUT_OF_MEMORY);

    char buffer[16];
    size_t readLength = 0;
    nabto_device_virtual_stream_read_all(virStream, fut, buffer, sizeof(buffer), &readLength);
    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_INVALID_STATE);
    nabto_device_virtual_stream_read_some(virStream, fut, buffer, sizeof(buffer), &readLength);
    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_INVALID_STATE);
    nabto_device_virtual_stream_write(virStream, fut, buffer, sizeof(buffer));
    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_INVALID_STATE);
    nabto_device_virtual_stream_close(virStream, fut);
    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_INVALID_STATE);
    nabto_device_virtual_stream_abort(virStream);

    nabto_device_future_free(fut);
    nabto_device_virtual_stream_free(virStream);
}

BOOST_AUTO_TEST_CASE(open_twice, *boost::unit_test::timeout(60))
{
    // Opening a stream again replaced the core stream of the first open,
    // which was leaked.
    nabto::test::TestStreamDevice td;
    nabto::test::TestStream ts(&td);
    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });
    td.makeConnection();
    NabtoDeviceVirtualStream* virStream = td.virtualStreamOpen();
    ts.futureWait(NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_virtual_stream_open(virStream, fut, td.streamPort_);
    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_INVALID_STATE);
    nabto_device_future_free(fut);

    ts.doRead();
    nabto_device_virtual_stream_abort(virStream);
    ts.futureWait(NABTO_DEVICE_EC_ABORTED);
}

BOOST_AUTO_TEST_SUITE_END()
