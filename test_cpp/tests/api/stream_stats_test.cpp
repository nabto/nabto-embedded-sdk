#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_virtual.h>
#include <nabto/nabto_device_experimental.h>
#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>

#include <cstring>

namespace nabto {
namespace test {

class StatsTestStreamDevice {
public:
    StatsTestStreamDevice()
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

    ~StatsTestStreamDevice()
    {
        if (virtStream_ != NULL) {
            nabto_device_virtual_stream_free(virtStream_);
        }
        if (connection_ != NULL) {
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

    static void stream_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        (void)fut;
        StatsTestStreamDevice* self = (StatsTestStreamDevice*)data;
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

    NabtoDevice* device_;
    NabtoDeviceVirtualConnection* connection_ = NULL;

    NabtoDeviceListener* streamListener_;
    NabtoDeviceFuture* newStreamFut_;
    std::function<void(NabtoDeviceError ec, NabtoDeviceStream* stream)> onStream_;
    NabtoDeviceStream* stream_;
    uint32_t streamPort_;

    NabtoDeviceVirtualStream* virtStream_ = NULL;
};

class StatsTestStream {
public:
    StatsTestStream(StatsTestStreamDevice* device)
    {
        device_ = device;
        future_ = nabto_device_future_new(device_->device_);
        buffer_ = (uint8_t*)calloc(1, 256);
        bufferLen_ = 256;
    }

    ~StatsTestStream()
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

    void futureWait(NabtoDeviceError expect)
    {
        NabtoDeviceError ec = nabto_device_future_wait(future_);
        BOOST_TEST(ec == expect);
    }

    StatsTestStreamDevice* device_;
    NabtoDeviceStream* stream_ = NULL;
    NabtoDeviceFuture* future_;
    uint8_t* buffer_;
    size_t bufferLen_;
    size_t readLen_;
};

}
} // namespace

BOOST_AUTO_TEST_SUITE(stream_stats)

BOOST_AUTO_TEST_CASE(received_bytes_initial_zero)
{
    nabto::test::StatsTestStreamDevice td;
    nabto::test::StatsTestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    uint64_t receivedBytes = 42;
    NabtoDeviceError ec = nabto_device_stream_stats_get_bytes_received(ts.stream_, &receivedBytes);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    BOOST_TEST(receivedBytes == (uint64_t)0);

    nabto_device_virtual_stream_abort(td.virtStream_);
}

BOOST_AUTO_TEST_CASE(sent_bytes_initial_zero)
{
    nabto::test::StatsTestStreamDevice td;
    nabto::test::StatsTestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    uint64_t sentBytes = 42;
    NabtoDeviceError ec = nabto_device_stream_stats_get_bytes_sent(ts.stream_, &sentBytes);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    BOOST_TEST(sentBytes == (uint64_t)0);

    nabto_device_virtual_stream_abort(td.virtStream_);
}

BOOST_AUTO_TEST_CASE(received_packets_initial_zero)
{
    nabto::test::StatsTestStreamDevice td;
    nabto::test::StatsTestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    uint64_t receivedPackets = 42;
    NabtoDeviceError ec = nabto_device_stream_stats_get_received_packets(ts.stream_, &receivedPackets);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    BOOST_TEST(receivedPackets == (uint64_t)0);

    nabto_device_virtual_stream_abort(td.virtStream_);
}

BOOST_AUTO_TEST_CASE(sent_packets_initial_zero)
{
    nabto::test::StatsTestStreamDevice td;
    nabto::test::StatsTestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    uint64_t sentPackets = 42;
    NabtoDeviceError ec = nabto_device_stream_stats_get_sent_packets(ts.stream_, &sentPackets);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    BOOST_TEST(sentPackets == (uint64_t)0);

    nabto_device_virtual_stream_abort(td.virtStream_);
}

BOOST_AUTO_TEST_CASE(lost_packets_initial_zero)
{
    nabto::test::StatsTestStreamDevice td;
    nabto::test::StatsTestStream ts(&td);

    td.streamListen([&](NabtoDeviceError ec, NabtoDeviceStream* stream) {
        if (ec == NABTO_DEVICE_EC_OK) {
            ts.acceptStream(stream);
        }
    });

    td.makeConnection();
    td.virtualStreamOpen();

    ts.futureWait(NABTO_DEVICE_EC_OK); // wait for accept

    uint64_t lostPackets = 42;
    NabtoDeviceError ec = nabto_device_stream_stats_get_lost_packets(ts.stream_, &lostPackets);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    BOOST_TEST(lostPackets == (uint64_t)0);

    nabto_device_virtual_stream_abort(td.virtStream_);
}

BOOST_AUTO_TEST_SUITE_END()
