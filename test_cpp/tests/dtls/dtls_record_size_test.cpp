#include <nabto/nabto_device_config.h>
#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#include <platform/np_completion_event.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_platform.h>

#include "../attach/certificates.hpp"

#include <deque>
#include <functional>
#include <future>
#include <vector>

#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY

namespace nabto {
namespace test {

/**
 * A device DTLS client connected to a device DTLS server through an in-memory
 * pipe. Every call into the DTLS modules is made from the platform event
 * thread.
 */
class DtlsPair {
 public:
    DtlsPair(TestPlatform& tp) : pl_(tp.getPlatform())
    {
        np_event_queue_create_event(&pl_->eq, &DtlsPair::deliver, this, &deliverEvent_);
        np_completion_event_init(&pl_->eq, &sendCtx_.ev, &DtlsPair::sent, this);
    }

    ~DtlsPair()
    {
        runOnEventThread([this]() {
            if (cli_ != NULL) {
                pl_->dtlsC.destroy_connection(cli_);
            }
            if (srvConn_ != NULL) {
                pl_->dtlsS.destroy_connection(srvConn_);
            }
            if (srv_ != NULL) {
                pl_->dtlsS.destroy(srv_);
            }
            toServer_.clear();
            toClient_.clear();
        });
        np_completion_event_deinit(&sendCtx_.ev);
        np_event_queue_destroy_event(&pl_->eq, deliverEvent_);
    }

    /**
     * @param noBuffersForCreate  No communication buffer can be allocated
     *                            while the connections are created, as when
     *                            a buffer pool is exhausted.
     */
    void connect(bool noBuffersForCreate = false)
    {
        const std::string& cert = localhostMultiNabtoNetCert;
        const std::string& key = privateKey;
        runOnEventThread([&]() {
            BOOST_REQUIRE(pl_->dtlsS.create(pl_, &srv_) == NABTO_EC_OK);
            BOOST_REQUIRE(pl_->dtlsS.set_keys(srv_, (const unsigned char*)cert.c_str(), cert.size(), (const unsigned char*)key.c_str(), key.size()) == NABTO_EC_OK);
            BOOST_REQUIRE(pl_->dtlsC.set_keys(pl_, (const unsigned char*)cert.c_str(), cert.size(), (const unsigned char*)key.c_str(), key.size()) == NABTO_EC_OK);

            struct np_communication_buffer* (*allocate)(void) = pl_->buf.allocate;
            if (noBuffersForCreate) {
                pl_->buf.allocate = []() -> struct np_communication_buffer* { return NULL; };
            }
            np_error_code srvEc = pl_->dtlsS.create_connection(srv_, &srvConn_, &DtlsPair::serverSender, &DtlsPair::serverData, &DtlsPair::serverEvent, this);
            np_error_code cliEc = pl_->dtlsC.create_client_connection(pl_, &cli_, &DtlsPair::clientSender, &DtlsPair::clientData, &DtlsPair::clientEvent, this);
            pl_->buf.allocate = allocate;
            BOOST_REQUIRE(srvEc == NABTO_EC_OK);
            BOOST_REQUIRE(cliEc == NABTO_EC_OK);

            BOOST_REQUIRE(pl_->dtlsC.connect(cli_) == NABTO_EC_OK);
        });
        BOOST_REQUIRE(handshake_.get_future().wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    }

    np_error_code clientSend(size_t size) { return send(size, true); }
    np_error_code serverSend(size_t size) { return send(size, false); }

    // Size of the last application packet delivered to the client and the
    // server respectively.
    size_t clientReceived_ = 0;
    size_t serverReceived_ = 0;

 private:
    np_error_code send(size_t size, bool fromClient)
    {
        payload_.assign(size, 0x42);
        sendCtx_.buffer = payload_.data();
        sendCtx_.bufferSize = (uint16_t)payload_.size();
        sendCtx_.channelId = NP_DTLS_DEFAULT_CHANNEL_ID;
        sentPromise_ = std::promise<np_error_code>();
        std::future<np_error_code> f = sentPromise_.get_future();
        runOnEventThread([&]() {
            np_error_code ec;
            if (fromClient) {
                ec = pl_->dtlsC.async_send_data(cli_, &sendCtx_);
            } else {
                ec = pl_->dtlsS.async_send_data(pl_, srvConn_, &sendCtx_);
            }
            if (ec != NABTO_EC_OK) {
                np_completion_event_resolve(&sendCtx_.ev, ec);
            }
        });
        BOOST_REQUIRE(f.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        np_error_code ec = f.get();
        // Let the record, if any, reach the peer.
        runOnEventThread([]() {});
        return ec;
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

    static np_error_code clientSender(uint8_t channelId, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* cb, void* data)
    {
        (void)channelId;
        DtlsPair* self = (DtlsPair*)data;
        self->toServer_.emplace_back(buffer, buffer + bufferSize);
        np_event_queue_post(&self->pl_->eq, self->deliverEvent_);
        np_completion_event_resolve(cb, NABTO_EC_OK);
        return NABTO_EC_OK;
    }

    static np_error_code serverSender(uint8_t channelId, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* cb, void* data)
    {
        (void)channelId;
        DtlsPair* self = (DtlsPair*)data;
        self->toClient_.emplace_back(buffer, buffer + bufferSize);
        np_event_queue_post(&self->pl_->eq, self->deliverEvent_);
        np_completion_event_resolve(cb, NABTO_EC_OK);
        return NABTO_EC_OK;
    }

    // Packets are handed to the peer from a separate event, so a DTLS
    // module is never re-entered from inside its own send callback.
    static void deliver(void* data)
    {
        DtlsPair* self = (DtlsPair*)data;
        while (!self->toServer_.empty() || !self->toClient_.empty()) {
            if (!self->toServer_.empty()) {
                std::vector<uint8_t> p = std::move(self->toServer_.front());
                self->toServer_.pop_front();
                self->pl_->dtlsS.handle_packet(self->pl_, self->srvConn_, NP_DTLS_DEFAULT_CHANNEL_ID, p.data(), (uint16_t)p.size());
            }
            if (!self->toClient_.empty()) {
                std::vector<uint8_t> p = std::move(self->toClient_.front());
                self->toClient_.pop_front();
                self->pl_->dtlsC.handle_packet(self->cli_, NP_DTLS_DEFAULT_CHANNEL_ID, p.data(), (uint16_t)p.size());
            }
        }
    }

    static void sent(np_error_code ec, void* data)
    {
        DtlsPair* self = (DtlsPair*)data;
        self->sentPromise_.set_value(ec);
    }

    static void clientEvent(enum np_dtls_event event, void* data)
    {
        DtlsPair* self = (DtlsPair*)data;
        if (event == NP_DTLS_EVENT_HANDSHAKE_COMPLETE) {
            self->handshake_.set_value();
        }
    }

    static void serverEvent(enum np_dtls_event event, void* data)
    {
        (void)event;
        (void)data;
    }

    static void clientData(uint8_t channelId, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data)
    {
        (void)channelId; (void)seq; (void)buffer;
        ((DtlsPair*)data)->clientReceived_ = bufferSize;
    }

    static void serverData(uint8_t channelId, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data)
    {
        (void)channelId; (void)seq; (void)buffer;
        ((DtlsPair*)data)->serverReceived_ = bufferSize;
    }

    struct np_platform* pl_;
    struct np_event* deliverEvent_ = NULL;
    struct np_dtls_srv* srv_ = NULL;
    struct np_dtls_srv_connection* srvConn_ = NULL;
    struct np_dtls_cli_connection* cli_ = NULL;
    std::deque<std::vector<uint8_t> > toServer_;
    std::deque<std::vector<uint8_t> > toClient_;
    std::promise<void> handshake_;
    struct np_dtls_send_context sendCtx_;
    std::vector<uint8_t> payload_;
    std::promise<np_error_code> sentPromise_;
};

} } // namespace

BOOST_AUTO_TEST_SUITE(dtls_record_size)

BOOST_AUTO_TEST_CASE(client_send_larger_than_communication_buffer)
{
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::DtlsPair pair(*tp);
    pair.connect();

    // A record for this payload does not fit in a communication buffer. It
    // must not be copied past the end of the buffer, and never reaches the
    // peer.
    np_error_code ec = pair.clientSend(1500);
#if defined(NABTO_DEVICE_MBEDTLS)
    // The mtu makes mbedtls refuse the data before a record is made.
    BOOST_TEST(ec != NABTO_EC_OK);
#else
    (void)ec;
#endif
    BOOST_TEST(pair.serverReceived_ == 0u);
}

BOOST_AUTO_TEST_CASE(server_send_larger_than_communication_buffer)
{
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::DtlsPair pair(*tp);
    pair.connect();

    np_error_code ec = pair.serverSend(1500);
#if defined(NABTO_DEVICE_MBEDTLS)
    BOOST_TEST(ec != NABTO_EC_OK);
#else
    (void)ec;
#endif
    BOOST_TEST(pair.clientReceived_ == 0u);
}

BOOST_AUTO_TEST_CASE(create_connection_without_free_communication_buffers)
{
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::DtlsPair pair(*tp);
    // Setting the mtu must not need a communication buffer.
    pair.connect(/*noBuffersForCreate*/ true);
}

BOOST_AUTO_TEST_CASE(max_plaintext_fits_in_a_record)
{
    auto tp = nabto::test::TestPlatform::create();
    struct np_platform* pl = tp->getPlatform();
    struct np_communication_buffer* buf = pl->buf.allocate();
    size_t maxPlaintext = pl->buf.size(buf) - NP_DTLS_MAX_RECORD_OVERHEAD;
    pl->buf.free(buf);

    nabto::test::DtlsPair pair(*tp);
    pair.connect();

    BOOST_TEST(pair.clientSend(maxPlaintext) == NABTO_EC_OK);
    BOOST_TEST(pair.serverReceived_ == maxPlaintext);
    BOOST_TEST(pair.serverSend(maxPlaintext) == NABTO_EC_OK);
    BOOST_TEST(pair.clientReceived_ == maxPlaintext);
}

BOOST_AUTO_TEST_SUITE_END()

#endif
