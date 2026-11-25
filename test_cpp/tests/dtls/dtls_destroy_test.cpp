#include <nabto/nabto_device_config.h>
#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_platform.h>

#include "../attach/certificates.hpp"

#include <nabto/nabto_device.h>
#include <util/io_service.hpp>
#include <util/live_allocations.hpp>

#include <boost/asio.hpp>

#include <functional>
#include <future>
#include <mutex>
#include <set>
#include <stdlib.h>
#include <vector>

// The ClientHello used here is rejected by mbedtls with an alert, wolfSSL
// first asks for a cookie.
#if defined(NABTO_DEVICE_MBEDTLS) && !defined(NABTO_DEVICE_DTLS_CLIENT_ONLY)

namespace {

/**
 * A DTLS server connection owned like nc_client_connection owns it: packets
 * are sent asynchronously and the connection is destroyed from the event
 * handler when it is closed.
 */
class ServerConnectionOwner {
 public:
    ServerConnectionOwner(nabto::test::TestPlatform& tp) : pl_(tp.getPlatform())
    {
        const std::string& cert = nabto::test::localhostMultiNabtoNetCert;
        const std::string& key = nabto::test::privateKey;
        runOnEventThread([&]() {
            BOOST_REQUIRE(pl_->dtlsS.create(pl_, &srv_) == NABTO_EC_OK);
            BOOST_REQUIRE(pl_->dtlsS.set_keys(srv_, (const unsigned char*)cert.c_str(), cert.size(), (const unsigned char*)key.c_str(), key.size()) == NABTO_EC_OK);
        });
    }

    ~ServerConnectionOwner()
    {
        runOnEventThread([this]() {
            if (conn_ != NULL) {
                pl_->dtlsS.destroy_connection(conn_);
            }
            pl_->dtlsS.destroy(srv_);
        });
    }

    void createConnection()
    {
        runOnEventThread([&]() {
            BOOST_REQUIRE(pl_->dtlsS.create_connection(srv_, &conn_, &ServerConnectionOwner::sender, &ServerConnectionOwner::dataHandler, &ServerConnectionOwner::eventHandler, this) == NABTO_EC_OK);
        });
    }

    void handlePacket(std::vector<uint8_t> packet)
    {
        runOnEventThread([&]() {
            pl_->dtlsS.handle_packet(pl_, conn_, NP_DTLS_DEFAULT_CHANNEL_ID, packet.data(), (uint16_t)packet.size());
        });
    }

    // Let the events posted so far, and the events they post, run.
    void drain()
    {
        for (int i = 0; i < 10; i++) {
            runOnEventThread([]() {});
        }
    }

    void runOnEventThread(std::function<void()> fn)
    {
        struct Ctx {
            std::function<void()> fn;
            std::promise<void> done;
        } ctx{fn, {}};
        struct np_event* ev = NULL;
        np_event_queue_create_event(&pl_->eq, [](void* d) {
            Ctx* c = (Ctx*)d;
            c->fn();
            c->done.set_value();
        }, &ctx, &ev);
        np_event_queue_post(&pl_->eq, ev);
        ctx.done.get_future().get();
        np_event_queue_destroy_event(&pl_->eq, ev);
    }

    std::vector<uint8_t> lastPacket_;
    size_t closedEvents_ = 0;
    size_t eventsAfterDestroy_ = 0;
    bool destroyed_ = false;

 private:
    // The packet is in flight until the owner resolves the completion event.
    static np_error_code sender(uint8_t channelId, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* cb, void* data)
    {
        (void)channelId;
        ServerConnectionOwner* self = (ServerConnectionOwner*)data;
        self->lastPacket_.assign(buffer, buffer + bufferSize);
        // The sender resolves the event later, so it takes it.
        np_completion_event_arm(cb);
        self->sentCb_ = cb;
        return NABTO_EC_OK;
    }

    static void eventHandler(enum np_dtls_event event, void* data)
    {
        ServerConnectionOwner* self = (ServerConnectionOwner*)data;
        if (self->destroyed_) {
            self->eventsAfterDestroy_++;
            return;
        }
        if (event == NP_DTLS_EVENT_CLOSED) {
            self->closedEvents_++;
            // Like nc_client_connection: the connection is destroyed while
            // the alert sent by the DTLS server is still in flight, and the
            // owner resolves the pending send as it goes away.
            self->pl_->dtlsS.destroy_connection(self->conn_);
            self->conn_ = NULL;
            self->destroyed_ = true;
            if (self->sentCb_ != NULL) {
                struct np_completion_event* cb = self->sentCb_;
                self->sentCb_ = NULL;
                np_completion_event_resolve(cb, NABTO_EC_ABORTED);
            }
        }
    }

    static void dataHandler(uint8_t channelId, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data)
    {
        (void)channelId; (void)seq; (void)buffer; (void)bufferSize; (void)data;
    }

    struct np_platform* pl_;
    struct np_dtls_srv* srv_ = NULL;
    struct np_dtls_srv_connection* conn_ = NULL;
    struct np_completion_event* sentCb_ = NULL;
};

/**
 * A DTLS 1.2 ClientHello which only offers TLS_RSA_WITH_AES_128_CBC_SHA, which
 * the device does not support.
 */
std::vector<uint8_t> clientHelloWithoutCommonCipherSuite()
{
    std::vector<uint8_t> body = { 0xfe, 0xfd }; // client_version DTLS 1.2
    body.insert(body.end(), 32, 0x42);          // random
    body.push_back(0x00);                       // session_id length
    body.push_back(0x00);                       // cookie length
    body.insert(body.end(), { 0x00, 0x02, 0x00, 0x2f }); // cipher_suites
    body.insert(body.end(), { 0x01, 0x00 });             // compression_methods

    uint8_t len = (uint8_t)body.size();
    std::vector<uint8_t> handshake = {
        0x01,             // client_hello
        0x00, 0x00, len,  // length
        0x00, 0x00,       // message_seq
        0x00, 0x00, 0x00, // fragment_offset
        0x00, 0x00, len   // fragment_length
    };
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record = {
        0x16,                               // handshake
        0xfe, 0xff,                         // DTLS 1.0 record version
        0x00, 0x00,                         // epoch
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence_number
        0x00, (uint8_t)handshake.size()     // length
    };
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}


} // namespace

BOOST_AUTO_TEST_SUITE(dtls_destroy)

BOOST_AUTO_TEST_CASE(server_connection_destroyed_while_alert_is_sent)
{
    auto tp = nabto::test::TestPlatform::create();
    ServerConnectionOwner owner(*tp);

    {
        nabto::test::LiveAllocations allocations;
        owner.createConnection();
        owner.handlePacket(clientHelloWithoutCommonCipherSuite());
        owner.drain();

        // The handshake failed, an alert was sent and the connection was
        // closed and destroyed while the alert was in flight.
        BOOST_TEST(owner.lastPacket_.size() > 0u);
        BOOST_TEST(owner.lastPacket_[0] == 21); // alert
        BOOST_TEST(owner.closedEvents_ == 1u);
        BOOST_TEST(owner.destroyed_);

        // The destroyed connection must not call its owner, and must be
        // freed once the pending send is resolved.
        BOOST_TEST(owner.eventsAfterDestroy_ == 0u);
        BOOST_TEST(allocations.live() == 0u);
    }
}

BOOST_AUTO_TEST_CASE(device_frees_client_connection_rejected_in_handshake, *boost::unit_test::timeout(60))
{
    nabto::test::LiveAllocations allocations;
    {
        NabtoDevice* device = nabto_device_new();
        BOOST_REQUIRE(device != NULL);
        nabto_device_set_product_id(device, "pr-abcdefgh");
        nabto_device_set_device_id(device, "de-12345678");
        nabto_device_set_local_port(device, 0);
        nabto_device_set_p2p_port(device, 0);
        char* key = NULL;
        BOOST_REQUIRE(nabto_device_create_private_key(device, &key) == NABTO_DEVICE_EC_OK);
        nabto_device_set_private_key(device, key);
        nabto_device_string_free(key);

        NabtoDeviceFuture* fut = nabto_device_future_new(device);
        nabto_device_start(device, fut);
        BOOST_REQUIRE(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OK);
        nabto_device_future_free(fut);

        uint16_t localPort = 0;
        nabto_device_get_local_port(device, &localPort);
        boost::asio::ip::udp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), localPort);

        auto ioService = nabto::IoService::create("test");
        boost::asio::ip::udp::socket socket(ioService->getIoService());
        socket.open(boost::asio::ip::udp::v4());

        // Each ClientHello opens a new client connection, which sends an
        // alert and is closed and destroyed while the alert is in flight.
        for (uint8_t i = 0; i < 3; i++) {
            std::vector<uint8_t> header = { 240 };
            header.insert(header.end(), 14, i);
            header.push_back(0); // channel id
            std::vector<uint8_t> packet = header;
            std::vector<uint8_t> clientHello = clientHelloWithoutCommonCipherSuite();
            packet.insert(packet.end(), clientHello.begin(), clientHello.end());
            socket.send_to(boost::asio::buffer(packet.data(), packet.size()), ep, 0);

            std::vector<uint8_t> response(1500);
            boost::asio::ip::udp::endpoint recvEp;
            size_t received = socket.receive_from(boost::asio::buffer(response.data(), response.size()), recvEp);
            BOOST_REQUIRE(received > 16u);
            BOOST_TEST(response[16] == 21); // alert record
        }

        nabto_device_stop(device);
        nabto_device_free(device);
        ioService->stop();
    }
    BOOST_TEST(allocations.live() == 0u);
}

BOOST_AUTO_TEST_SUITE_END()

#endif
