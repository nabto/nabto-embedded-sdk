#pragma once

/**
 * DTLS server
 *
 * udp data is going throgh this server and then dispatched to the
 * application.
 */

#include "certificate_context.hpp"
#include "alpn_protocols.hpp"
#include "dtls_server.hpp"
#include "mbedtls_timer.hpp"
#include "keep_alive.hpp"

#include <fixtures/udp_server/udp_server.hpp>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>

#include <util/span.hpp>
#include <boost/asio.hpp>
#include <boost/optional.hpp>

#include <chrono>
#include <memory>
#include <map>
#include <array>
#include <set>

namespace nabto {

class DtlsServerImpl;

class DtlsConnectionImpl;
typedef std::shared_ptr<DtlsConnectionImpl> DtlsConnectionImplPtr;

class DtlsServerImpl;
typedef std::shared_ptr<DtlsServerImpl> DtlsServerImplPtr;

class CoapHandler {
 public:

    CoapHandler(std::shared_ptr<DtlsServerImpl> dtlsServer) : dtlsServer_(dtlsServer) {}
    std::shared_ptr<DtlsServerImpl> dtlsServer_;

    std::string path_;
    std::function<void (DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)> handler_;

    static void handleRequest(struct nabto_coap_server_request* request, void* userData);
};

class DtlsConnectionImpl : public DtlsConnection, public coap::CoapConnection, public std::enable_shared_from_this<DtlsConnectionImpl> {
 public:
    enum State {
        COOKIE_VERIFY,
        HANDSHAKE,
        DATA,
        CLOSED,
        SERROR
    };

    DtlsConnectionImpl(boost::asio::io_context& ioContext, DtlsServerImplPtr server, const boost::asio::ip::udp::endpoint& ep, const std::string& connectionName);

    virtual ~DtlsConnectionImpl();

    static DtlsConnectionImplPtr create(boost::asio::io_context& ioContext, DtlsServerImplPtr server, const boost::asio::ip::udp::endpoint& ep);

    void dispatch(lib::span<const uint8_t> buffer);

    uint16_t getMtu() { return 1024; }

    void coapAsyncSend(lib::span<const uint8_t> packet, SendHandler handler)
    {
        asyncSendApplicationData(packet, handler);
    }

 private:
    bool init(const boost::asio::ip::udp::endpoint& ep);

    void run();
 public:
    typedef std::function<void (const boost::system::error_code& ec, lib::span<const uint8_t> data)> DatagramHandler;
    typedef std::function<void (const boost::system::error_code& ec)> DatagramSentHandler;

    void setRelayPacketHandler(DatagramHandler dh)
    {
        relayDataHandler_ = dh;
    }

    void resetRelayPacketHandler()
    {
        relayDataHandler_ = nullptr;
    }

    void asyncSendApplicationData(lib::span<const uint8_t> data, DatagramSentHandler dsh);

    // void asyncReceiveRelayPacket(DatagramHandler dh)
    // {
    //     relayRecvQueue_.asyncPop([dh](const lib::error_code& ec, const std::vector<uint8_t>& packet) {
    //             dh(ec, lib::span<const uint8_t>(packet.data(), packet.size()));
    //         });
    // }
    void asyncSendRelayPacket(lib::span<const uint8_t> packet, DatagramSentHandler dsh);


    void asyncClose(std::function<void (const lib::error_code& ec)> cb);

    void stopFromManager();

    std::string getAlpnProtocol();
    lib::optional<std::array<uint8_t, 32> > getOtherPeerFingerprint();

    void accessDenied();

 private:
    void doOne();

    void asyncSend(std::shared_ptr<std::vector<uint8_t> > data);

    /**
     * return number of bytes sent. return MBEDTLS_ERR_SSL_WANT_WRITE if we would have blocked.
     */
    static int mbedSend(void* ctx, const unsigned char* buffer, size_t bufferSize);

    /**
     * return number of bytes read or MBEDTLS_ERR_SSL_WANT_READ if it
     * would have blocked.
     */
    static int mbedRecv(void* ctx, unsigned char* buffer, size_t bufferSize);

    void handleTimeout();
    void handleHandshakePacket(lib::span<const uint8_t> packet);
    void handleDataPacket(lib::span<const uint8_t> packet);

    void closeFromSelf();

    void startKeepAlive();

 private:
    boost::asio::io_context& io_;
    DtlsServerImplPtr server_;
 public:
    boost::asio::ip::udp::endpoint ep_;
    CertificateContextPtr certificateContext_;

 private:
    // timing
    MbedTlsTimer timer_;



 public:
    mbedtls_ssl_context ssl_;
 private:

    lib::span<const uint8_t> recvBuffer_;


    DatagramHandler appDataHandler_;
    DatagramHandler relayDataHandler_;

//    AsyncQueue<std::vector<uint8_t> > relayRecvQueue_;

    KeepAlive keepAlive_;

    std::atomic<uint64_t> dtlsRecvCount_ = { 0 };
    std::atomic<uint64_t> dtlsSentCount_ = { 0 };

    uint64_t keepAliveCount_ = 0;


    std::string connectionName_;

 public:
    State state_ = COOKIE_VERIFY;
};

class DtlsServerImpl : public std::enable_shared_from_this<DtlsServerImpl> {

 public:

    DtlsServerImpl(boost::asio::io_context& ioContext);
    DtlsServerImpl(boost::asio::io_context& ioContext, std::string ip);
    ~DtlsServerImpl();

    typedef std::function<void (const std::string& sni)> sniCb;

    lib::error_code init();

    lib::error_code initConfig();

    std::unique_ptr<mbedtls_ssl_context> createContext();

    void setPort(uint16_t port) { port_ = port; }
    uint16_t getPort() { return udpServer_.port(); };

    void setAlpnProtocols(std::vector<std::string> alpns) {
        alpnProtocols_ = std::make_unique<AlpnProtocols>(alpns);
    }


    void setSniCallback(DtlsServer::SniCallback sniCallback) { sniCallback_ = sniCallback; }

    void setKeepAliveSettings(KeepAliveSettings keepAliveSettings) { keepAliveSettings_ = keepAliveSettings; }
    void setHandshakeTimeout(uint32_t min, uint32_t max) { minHandshakeTimeout_ = min; maxHandshakeTimeout_ = max; }

    void startReceive();
    void closeConnection(DtlsConnectionImplPtr connection);

    void connectionClosed(DtlsConnectionImplPtr connection);

    void connectionEnteredDataPhase(DtlsConnectionImplPtr connection);

    static int mbedSni(void* server, mbedtls_ssl_context* ctx, const unsigned char* sni, size_t sniLength);

    mbedtls_ssl_config conf_;
    std::unique_ptr<AlpnProtocols> alpnProtocols_;

    std::shared_ptr<CertificateContext> getSniConfig(const std::string& sni);
    DtlsConnectionImplPtr getConnection(const mbedtls_ssl_context* ssl);

    void addResourceHandler(nabto_coap_code method, const std::string& path, std::function<void (DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)> handler);

    std::shared_ptr<coap::CoapServer> getCoapServer() {
        return coapServer_;
    }

    DtlsConnectionPtr getConnectionFromCoapConnection(void* connection);

    void handleCoapPacket(DtlsConnectionImplPtr connection, lib::span<const uint8_t> packet);

    void stop()
    {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        udpServer_.close();
        coapServer_->stop();

        std::vector<DtlsConnectionImplPtr> handshakeConnections;
        std::vector<DtlsConnectionImplPtr> dataConnections;

        for (auto c : handshakeConnectionMap_) {
            handshakeConnections.push_back(c.second);
        }
        for (auto c : dataConnectionMap_) {
            dataConnections.push_back(c.second);
        }

        handshakeConnectionMap_.clear();
        dataConnectionMap_.clear();
        connectionMapSslCtx_.clear();
        for (auto conn : handshakeConnections) {
            conn->stopFromManager();
        }

        for (auto conn : dataConnections) {
            conn->stopFromManager();
            if (connectionClosedHandler_) {
                connectionClosedHandler_(conn);
            }
        }
        connectionClosedHandler_ = NULL;
        coapHandlers_.clear();
    }

    void asyncNiceClose(std::function<void (const lib::error_code& ec)> cb)
    {
        std::shared_ptr<std::set<DtlsConnectionImplPtr> > cs = std::make_shared<std::set<DtlsConnectionImplPtr> >();
        for (auto c : handshakeConnectionMap_) {
            cs->insert(c.second);
        }
        for (auto c : dataConnectionMap_) {
            cs->insert(c.second);
        }

        for (auto c : *cs) {
            c->asyncClose([c, cs, cb](const lib::error_code& /*ec*/){
                    cs->erase(c);
                    if (cs->empty()) {
                        cb(make_error_code(TestError::ok));
                    }
                });
        }
    }

    void setConnectionClosedHandler(std::function<void (DtlsConnectionPtr connection)> cb)
    {
        connectionClosedHandler_ = cb;
    }
 private:

    void handlePacket(const boost::asio::ip::udp::endpoint& ep, lib::span<const uint8_t> packet);

    boost::asio::io_context& ioContext_;
 public:
    UdpServer udpServer_;
 private:
    uint16_t port_ = 0;

    boost::asio::ip::udp::endpoint recvEp_;
    std::array<uint8_t, 1500> recvBuffer_;

    std::map<boost::asio::ip::udp::endpoint, DtlsConnectionImplPtr> handshakeConnectionMap_;
    std::map<boost::asio::ip::udp::endpoint, DtlsConnectionImplPtr> dataConnectionMap_;
    std::map<const mbedtls_ssl_context*, DtlsConnectionImplPtr> connectionMapSslCtx_;

    DtlsServer::SniCallback sniCallback_;

    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_timing_delay_context timer;

    std::set<boost::asio::ip::udp::endpoint> whiteList_;

    std::shared_ptr<coap::CoapServer> coapServer_;

    std::vector<std::shared_ptr<CoapHandler> > coapHandlers_;

    std::function<void (DtlsConnectionPtr connection)> connectionClosedHandler_;

    bool stopped_ = false;
 public:
    KeepAliveSettings keepAliveSettings_;
    uint32_t minHandshakeTimeout_ = 1000;
    uint32_t maxHandshakeTimeout_ = 60000;

};

} // namespace
