#include <nabto/nabto_device_config.h>
#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#include <platform/np_completion_event.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_platform.h>

#include "../attach/certificates.hpp"

#include <chrono>
#include <deque>
#include <functional>
#include <future>
#include <thread>
#include <vector>

#if !defined(NABTO_DEVICE_DTLS_CLIENT_ONLY) && defined(NABTO_DEVICE_MBEDTLS)

namespace nabto {
namespace test {

typedef std::vector<uint8_t> Packet;

/**
 * A device DTLS client and the DTLS server module, where the test decides
 * which packets are delivered. Every call into the DTLS modules is made from
 * the platform event thread.
 */
class HelloVerifyHarness {
 public:
    HelloVerifyHarness(TestPlatform& tp) : pl_(tp.getPlatform())
    {
        np_event_queue_create_event(&pl_->eq, &HelloVerifyHarness::deliver, this, &deliverEvent_);
        const std::string& cert = localhostMultiNabtoNetCert;
        const std::string& key = privateKey;
        run([&]() {
            BOOST_REQUIRE(pl_->dtlsS.create(pl_, &srv_) == NABTO_EC_OK);
            BOOST_REQUIRE(pl_->dtlsS.set_keys(srv_, (const unsigned char*)cert.c_str(), cert.size(), (const unsigned char*)key.c_str(), key.size()) == NABTO_EC_OK);
            BOOST_REQUIRE(pl_->dtlsC.set_keys(pl_, (const unsigned char*)cert.c_str(), cert.size(), (const unsigned char*)key.c_str(), key.size()) == NABTO_EC_OK);
            BOOST_REQUIRE(pl_->dtlsC.create_client_connection(pl_, &cli_, &HelloVerifyHarness::clientSender, &HelloVerifyHarness::clientData, &HelloVerifyHarness::clientEvent, this) == NABTO_EC_OK);
        });
    }

    ~HelloVerifyHarness()
    {
        run([this]() {
            pl_->dtlsC.destroy_connection(cli_);
            if (srvConn_ != NULL) {
                pl_->dtlsS.destroy_connection(srvConn_);
            }
            pl_->dtlsS.destroy(srv_);
            toServer_.clear();
            toClient_.clear();
        });
        np_event_queue_destroy_event(&pl_->eq, deliverEvent_);
    }

    // Start the client and return its first ClientHello.
    Packet connect()
    {
        run([this]() { BOOST_REQUIRE(pl_->dtlsC.connect(cli_) == NABTO_EC_OK); });
        return nextToServer();
    }

    // Give a packet to the client and return the next packet it sends.
    Packet toClient(const Packet& p)
    {
        run([&]() {
            Packet copy = p;
            pl_->dtlsC.handle_packet(cli_, NP_DTLS_DEFAULT_CHANNEL_ID, copy.data(), (uint16_t)copy.size());
        });
        return nextToServer();
    }

    np_error_code verify(const std::vector<uint8_t>& clientId, const Packet& p, Packet& response)
    {
        np_error_code ec = NABTO_EC_FAILED;
        run([&]() {
            uint8_t buffer[NP_DTLS_SRV_MAX_HELLO_VERIFY_SIZE];
            size_t size = 0;
            ec = pl_->dtlsS.verify_client_hello(srv_, clientId.data(), clientId.size(), p.data(), p.size(), buffer, &size);
            response.assign(buffer, buffer + size);
        });
        return ec;
    }

    // Create the server connection, give it the ClientHello and let the
    // client and server exchange the rest of the handshake.
    void handshake(const std::vector<uint8_t>& clientId, const Packet& clientHello)
    {
        run([&]() {
            BOOST_REQUIRE(pl_->dtlsS.create_connection(srv_, clientId.data(), clientId.size(), &srvConn_, &HelloVerifyHarness::serverSender, &HelloVerifyHarness::serverData, &HelloVerifyHarness::serverEvent, this) == NABTO_EC_OK);
            toServer_.clear();
            autoDeliver_ = true;
            Packet copy = clientHello;
            pl_->dtlsS.handle_packet(pl_, srvConn_, NP_DTLS_DEFAULT_CHANNEL_ID, copy.data(), (uint16_t)copy.size());
        });
        BOOST_REQUIRE(handshake_.get_future().wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    }

    // All packets the server connection has sent.
    std::vector<Packet> fromServer_;

 private:
    Packet nextToServer()
    {
        for (int i = 0; i < 5000; i++) {
            Packet p;
            run([&]() {
                if (!toServer_.empty()) {
                    p = toServer_.front();
                    toServer_.pop_front();
                }
            });
            if (!p.empty()) {
                return p;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        BOOST_FAIL("The client did not send a packet");
        return Packet();
    }

    void run(std::function<void()> fn)
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

    static np_error_code clientSender(uint8_t channelId, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* cb, void* data)
    {
        (void)channelId;
        HelloVerifyHarness* self = (HelloVerifyHarness*)data;
        self->toServer_.emplace_back(buffer, buffer + bufferSize);
        if (self->autoDeliver_) {
            np_event_queue_post(&self->pl_->eq, self->deliverEvent_);
        }
        np_completion_event_resolve(cb, NABTO_EC_OK);
        return NABTO_EC_OK;
    }

    static np_error_code serverSender(uint8_t channelId, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* cb, void* data)
    {
        (void)channelId;
        HelloVerifyHarness* self = (HelloVerifyHarness*)data;
        self->fromServer_.emplace_back(buffer, buffer + bufferSize);
        self->toClient_.emplace_back(buffer, buffer + bufferSize);
        np_event_queue_post(&self->pl_->eq, self->deliverEvent_);
        np_completion_event_resolve(cb, NABTO_EC_OK);
        return NABTO_EC_OK;
    }

    // Packets are handed to the peer from a separate event, so a DTLS
    // module is never re-entered from inside its own send callback.
    static void deliver(void* data)
    {
        HelloVerifyHarness* self = (HelloVerifyHarness*)data;
        while (!self->toServer_.empty() || !self->toClient_.empty()) {
            if (!self->toServer_.empty()) {
                Packet p = std::move(self->toServer_.front());
                self->toServer_.pop_front();
                self->pl_->dtlsS.handle_packet(self->pl_, self->srvConn_, NP_DTLS_DEFAULT_CHANNEL_ID, p.data(), (uint16_t)p.size());
            }
            if (!self->toClient_.empty()) {
                Packet p = std::move(self->toClient_.front());
                self->toClient_.pop_front();
                self->pl_->dtlsC.handle_packet(self->cli_, NP_DTLS_DEFAULT_CHANNEL_ID, p.data(), (uint16_t)p.size());
            }
        }
    }

    static void clientEvent(enum np_dtls_event event, void* data)
    {
        HelloVerifyHarness* self = (HelloVerifyHarness*)data;
        if (event == NP_DTLS_EVENT_HANDSHAKE_COMPLETE) {
            self->handshake_.set_value();
        }
    }

    static void serverEvent(enum np_dtls_event event, void* data) { (void)event; (void)data; }
    static void clientData(uint8_t channelId, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data) { (void)channelId; (void)seq; (void)buffer; (void)bufferSize; (void)data; }
    static void serverData(uint8_t channelId, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data) { (void)channelId; (void)seq; (void)buffer; (void)bufferSize; (void)data; }

    struct np_platform* pl_;
    struct np_event* deliverEvent_ = NULL;
    struct np_dtls_srv* srv_ = NULL;
    struct np_dtls_srv_connection* srvConn_ = NULL;
    struct np_dtls_cli_connection* cli_ = NULL;
    bool autoDeliver_ = false;
    std::deque<Packet> toServer_;
    std::deque<Packet> toClient_;
    std::promise<void> handshake_;
};

static const std::vector<uint8_t> clientA = { 4, 127, 0, 0, 1, 0x12, 0x34, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
static const std::vector<uint8_t> clientB = { 4, 127, 0, 0, 1, 0x12, 0x35, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

static const size_t handshakeTypeOffset = 13;

} } // namespace

BOOST_AUTO_TEST_SUITE(dtls_hello_verify)

BOOST_AUTO_TEST_CASE(cookie_exchange_before_connection)
{
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::HelloVerifyHarness h(*tp);

    nabto::test::Packet hello1 = h.connect();
    nabto::test::Packet hvr;
    BOOST_TEST(h.verify(nabto::test::clientA, hello1, hvr) == NABTO_EC_OPERATION_STARTED);
    // The answer to an unverified peer must be smaller than its request.
    BOOST_TEST(hvr.size() < hello1.size());
    BOOST_TEST(hvr.size() <= (size_t)NP_DTLS_SRV_MAX_HELLO_VERIFY_SIZE);
    BOOST_TEST(hvr[0] == 22);
    BOOST_TEST(hvr[nabto::test::handshakeTypeOffset] == 3);

    nabto::test::Packet hello2 = h.toClient(hvr);
    nabto::test::Packet unused;
    BOOST_TEST(h.verify(nabto::test::clientA, hello2, unused) == NABTO_EC_OK);
    // The cookie is bound to the address of the peer.
    BOOST_TEST(h.verify(nabto::test::clientB, hello2, unused) == NABTO_EC_OPERATION_STARTED);

    h.handshake(nabto::test::clientA, hello2);
    // The connection accepted the cookie, so it answered with a ServerHello
    // and not another HelloVerifyRequest.
    BOOST_REQUIRE(!h.fromServer_.empty());
    BOOST_TEST(h.fromServer_[0][nabto::test::handshakeTypeOffset] == 2);
}

BOOST_AUTO_TEST_CASE(connection_without_cookie_asks_for_one)
{
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::HelloVerifyHarness h(*tp);

    // A connection created without the stateless check does the cookie
    // exchange itself before the handshake completes.
    nabto::test::Packet hello1 = h.connect();
    h.handshake(nabto::test::clientA, hello1);
    BOOST_REQUIRE(!h.fromServer_.empty());
    BOOST_TEST(h.fromServer_[0][nabto::test::handshakeTypeOffset] == 3);
}

BOOST_AUTO_TEST_CASE(malformed_client_hello_is_dropped)
{
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::HelloVerifyHarness h(*tp);
    nabto::test::Packet hello = h.connect();
    nabto::test::Packet response;

    for (size_t i = 0; i < hello.size(); i++) {
        nabto::test::Packet truncated(hello.begin(), hello.begin() + (std::ptrdiff_t)i);
        BOOST_TEST(h.verify(nabto::test::clientA, truncated, response) == NABTO_EC_MALFORMED_PACKET);
        BOOST_TEST(response.empty());
    }

    nabto::test::Packet notHandshake = hello;
    notHandshake[0] = 23;
    BOOST_TEST(h.verify(nabto::test::clientA, notHandshake, response) == NABTO_EC_MALFORMED_PACKET);

    nabto::test::Packet notClientHello = hello;
    notClientHello[nabto::test::handshakeTypeOffset] = 2;
    BOOST_TEST(h.verify(nabto::test::clientA, notClientHello, response) == NABTO_EC_MALFORMED_PACKET);

    nabto::test::Packet fragment = hello;
    fragment[13 + 8] = 1; // fragment_offset
    BOOST_TEST(h.verify(nabto::test::clientA, fragment, response) == NABTO_EC_MALFORMED_PACKET);

    nabto::test::Packet longRecord = hello;
    longRecord[11] = 0xff; // record length
    BOOST_TEST(h.verify(nabto::test::clientA, longRecord, response) == NABTO_EC_MALFORMED_PACKET);

    // session_id length is the byte after the 12 byte handshake header,
    // client_version and random.
    nabto::test::Packet longSessionId = hello;
    longSessionId[13 + 12 + 2 + 32] = 33;
    BOOST_TEST(h.verify(nabto::test::clientA, longSessionId, response) == NABTO_EC_MALFORMED_PACKET);

    nabto::test::Packet badCookie = hello;
    size_t cookieLengthOffset = 13 + 12 + 2 + 32 + 1 + hello[13 + 12 + 2 + 32];
    badCookie[cookieLengthOffset] = 0xff;
    BOOST_TEST(h.verify(nabto::test::clientA, badCookie, response) == NABTO_EC_MALFORMED_PACKET);
    BOOST_TEST(response.empty());
}

BOOST_AUTO_TEST_SUITE_END()

#endif
