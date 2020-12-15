#include "dtls_server_impl.hpp"
#include "mbedtls_util.hpp"
#include "dtls_error_codes.hpp"
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

#include <iostream>
#include <memory>
#include <boost/algorithm/string.hpp>


namespace nabto {

class CoapServerRequestImpl : public CoapServerRequest {
 public:
    CoapServerRequestImpl(struct nabto_coap_server_request* request)
        : request_(request)
    {

    }
    ~CoapServerRequestImpl() {
        nabto_coap_server_request_free(request_);
    }

    struct nabto_coap_server_request* getRequest() {
        return request_;
    }

    virtual std::vector<uint8_t> getPayload()
    {
        uint8_t* payload;
        size_t payloadLength;
        if (!nabto_coap_server_request_get_payload(request_, (void**)&payload, &payloadLength)) {
            return std::vector<uint8_t>();
        }

        return std::vector<uint8_t>(payload, payload+payloadLength);
    }

    virtual int32_t getContentFormat()
    {
        return nabto_coap_server_request_get_content_format(request_);
    }

    virtual std::string getParameter(const std::string& id)
    {
        const char* v = nabto_coap_server_request_get_parameter(request_, id.c_str());
        if (v != NULL) {
            return std::string(v);
        }
        return "";
    }

 private:
    struct nabto_coap_server_request* request_;
};


class CoapServerResponseImpl : public CoapServerResponse {
 public:
    CoapServerResponseImpl(std::shared_ptr<CoapServerRequestImpl> request)
        : request_(request)
    {
    }
    virtual ~CoapServerResponseImpl() {
        if (codeIsSet_) {
            nabto_coap_server_response_ready(getRequest());
        }
    }

    virtual void setContentFormat(uint16_t contentFormat)
    {
        nabto_coap_server_response_set_content_format(getRequest(), contentFormat);
    }
    virtual void setCode(uint16_t code)
    {
        codeIsSet_ = true;
        nabto_coap_server_response_set_code_human(getRequest(), code);
    }
    virtual void setPayload(lib::span<const uint8_t> payload)
    {
        nabto_coap_server_response_set_payload(getRequest(), payload.data(), payload.size());
    }

    struct nabto_coap_server_request* getRequest() {
        return request_->getRequest();
    }

 private:
    bool codeIsSet_ = false;
    std::shared_ptr<CoapServerRequestImpl> request_;
};

void CoapHandler::handleRequest(struct nabto_coap_server_request* request, void* userData)
{
    CoapHandler* handler = (CoapHandler*)(userData);
    void* connection = nabto_coap_server_request_get_connection(request);
    DtlsConnectionPtr dtlsConnection = handler->dtlsServer_->getConnectionFromCoapConnection(connection);
    auto requestImpl = std::make_shared<CoapServerRequestImpl>(request);
    auto responseImpl = std::make_shared<CoapServerResponseImpl>(requestImpl);
    handler->handler_(dtlsConnection, requestImpl, responseImpl);
}

void DtlsServerImpl::addResourceHandler(nabto_coap_code method, const std::string& path, std::function<void (DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)> handler)
{
    auto coapHandler = std::make_shared<CoapHandler>(shared_from_this());
    coapHandler->path_ = path;
    coapHandler->handler_ = handler;
    coapHandlers_.push_back(coapHandler);

    std::vector<std::string> pathSegmentStrings;
    boost::split(pathSegmentStrings, path, boost::is_any_of("/"));

    std::vector<const char*> pathSegments;

    for (auto& s : pathSegmentStrings) {
        if (!s.empty()) {
            pathSegments.push_back(s.c_str());
        }
    }
    pathSegments.push_back(NULL);

    nabto_coap_error err = coapServer_->addResource(method, pathSegments.data(), &CoapHandler::handleRequest, coapHandler.get() );
    if (err != NABTO_COAP_ERROR_OK) {
        coapHandlers_.pop_back();
    }
}



DtlsConnectionPtr DtlsServerImpl::getConnectionFromCoapConnection(void* connection)
{
    return std::dynamic_pointer_cast<DtlsConnection>(coapServer_->getConnection(connection));
}

void DtlsServerImpl::handleCoapPacket(DtlsConnectionImplPtr connection, lib::span<const uint8_t> packet)
{
    coapServer_->handlePacket(connection, packet);
}

DtlsServerImpl::DtlsServerImpl(boost::asio::io_context& ioContext)
    : ioContext_(ioContext),
      udpServer_(ioContext),
      coapServer_(coap::CoapServer::create(ioContext))
{
    mbedtls_ssl_config_init( &conf_ );
    mbedtls_ssl_cookie_init( &cookie_ctx );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
}

DtlsServerImpl::DtlsServerImpl(boost::asio::io_context& ioContext, std::string ip)
    : ioContext_(ioContext),
      udpServer_(ioContext, ip),
      coapServer_(coap::CoapServer::create(ioContext))
{
    mbedtls_ssl_config_init( &conf_ );
    mbedtls_ssl_cookie_init( &cookie_ctx );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
}

DtlsServerImpl::~DtlsServerImpl()
{
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_ssl_cookie_free( &cookie_ctx );
    mbedtls_ssl_config_free( &conf_ );
}

// todo: dont use both std::cout and printf when we also have logger_
lib::error_code DtlsServerImpl::initConfig()
{
    const char *pers = "dtls_server";

    mbedTlsSetDebugLevelFromEnv();

    int ret;

    if( ( ret = mbedtls_ssl_config_defaults( &conf_,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        std::cout << " failed\n  ! mbedtls_ssl_config_defaults returned  " << ret << std::endl;
        return make_error_code(DtlsError::set_default_config);
    }

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return make_error_code(DtlsError::random_seeding_failed);
    }

    mbedtls_ssl_conf_dbg( &conf_, mbedTlsLogger, NULL); // TODO: maybe add log context
    mbedtls_ssl_conf_rng( &conf_, mbedtls_ctr_drbg_random, &ctr_drbg );


    if( ( ret = mbedtls_ssl_cookie_setup( &cookie_ctx,
                                          mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret );
        return make_error_code(DtlsError::cookie_setup);
    }

    mbedtls_ssl_conf_dtls_cookies( &conf_, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                   &cookie_ctx );

    mbedtls_ssl_conf_sni(&conf_, &DtlsServerImpl::mbedSni, this);

    if (alpnProtocols_) {
        mbedtls_ssl_conf_alpn_protocols(&conf_, alpnProtocols_->getProtocols() );
    }
    mbedtls_ssl_conf_handshake_timeout( &conf_, minHandshakeTimeout_, maxHandshakeTimeout_);
    return make_error_code(DtlsError::ok);
}


lib::error_code DtlsServerImpl::init()
{
    if (!sniCallback_) {
        return make_error_code(DtlsError::missing_sni_callback);
    }

    boost::system::error_code ec;
    udpServer_.open(port_, ec);
    if (ec) {
        return ec;
    }
    initConfig();
    startReceive();
    return make_error_code(DtlsError::ok);
}

int DtlsServerImpl::mbedSni(void* server, mbedtls_ssl_context* ssl, const unsigned char* sni, size_t sniLength)
{
    auto dtlsServer = reinterpret_cast<DtlsServerImpl*>(server);

    std::string sniName(reinterpret_cast<const char*>(sni), sniLength);

    if (!dtlsServer->sniCallback_) {
        return 0;
    }

    std::shared_ptr<CertificateContext> ctx = dtlsServer->sniCallback_(sniName);
    std::shared_ptr<DtlsConnectionImpl> connection = dtlsServer->getConnection(ssl);

    if (!ctx) {
        return -1;
    }

    if (!connection) {
        return -1;
    }

    connection->certificateContext_ = ctx;

    mbedtls_ssl_set_hs_authmode( ssl, ctx->authMode );

    int ret = mbedtls_ssl_set_hs_own_cert( ssl, &ctx->publicKey_, &ctx->privateKey_ );
    if (ret != 0) {
        return ret;
    }

    return 0;
}

std::shared_ptr<DtlsConnectionImpl> DtlsServerImpl::getConnection(const mbedtls_ssl_context* ssl)
{
    auto it = connectionMapSslCtx_.find(ssl);
    if (it == connectionMapSslCtx_.end()) {
        return nullptr;
    }
    return it->second;
}

void DtlsServerImpl::closeConnection(DtlsConnectionImplPtr connection)
{
    auto self = shared_from_this();
    ioContext_.post([connection, self](){
            connection->asyncClose([connection, self](const lib::error_code& /*ec*/){
                });
        });
}

void DtlsServerImpl::connectionClosed(DtlsConnectionImplPtr connection)
{
    coapServer_->removeConnection(connection);
    for (auto c : handshakeConnectionMap_) {
        if (c.second == connection) {
            handshakeConnectionMap_.erase(c.first);
            break;
        }
    }
    for (auto c : dataConnectionMap_) {
        if (c.second == connection) {
            dataConnectionMap_.erase(c.first);
            if (connectionClosedHandler_) {
                connectionClosedHandler_(connection);
            }
            break;
        }
    }

    connectionMapSslCtx_.erase(&connection->ssl_);
}

void DtlsServerImpl::connectionEnteredDataPhase(DtlsConnectionImplPtr connection)
{
    // upgrade a connection to a data connection, if a previous
    // connection exists at this point, it will be overtaken by this
    // new connection.
    boost::asio::ip::udp::endpoint ep = connection->ep_;
    if (dataConnectionMap_.find(ep) != dataConnectionMap_.end()) {
        auto c = dataConnectionMap_[ep];
        c->stopFromManager();
        connectionClosed(c);
    }
    handshakeConnectionMap_.erase(ep);
    dataConnectionMap_[ep] = connection;
}

void DtlsServerImpl::startReceive()
{
    if (stopped_) {
        return;
    }
    auto self = shared_from_this();
    udpServer_.asyncReceive(lib::span<uint8_t>(recvBuffer_), recvEp_, [self](const boost::system::error_code& ec, std::size_t transferred) {
            if (ec) {
                return;
            } else if ( transferred == 0 ) {
                return;
            } else {
                lib::span<uint8_t> received(self->recvBuffer_.data(), transferred);
                self->handlePacket(self->recvEp_, received);
                self->startReceive();
            }
        });
}

void DtlsServerImpl::handlePacket(const boost::asio::ip::udp::endpoint& ep, lib::span<const uint8_t> received)
{
    if (stopped_) {
        return;
    }

    // dispatch the packet to both current data connections and new
    // handshakes, this is useful if a device is establishing a new
    // connection using a previously used ip:port combination.

    if (dataConnectionMap_.find(ep) != dataConnectionMap_.end()) {
        DtlsConnectionImplPtr conn = dataConnectionMap_[ep];
        conn->dispatch(received);
    }


    if (handshakeConnectionMap_.find(ep) != handshakeConnectionMap_.end()) {
        DtlsConnectionImplPtr conn = handshakeConnectionMap_[ep];
        conn->dispatch(received);
    } else if (received[0] == 22 && received[13] == 1) {
        // match dtls handshake and client_hello record type
        DtlsConnectionImplPtr conn = DtlsConnectionImpl::create(ioContext_, shared_from_this(), ep);
        if (conn) {
            connectionMapSslCtx_[&conn->ssl_] = conn;
            conn->dispatch(received);
            if (conn->state_ > DtlsConnectionImpl::COOKIE_VERIFY && conn->state_ < DtlsConnectionImpl::CLOSED) {
                handshakeConnectionMap_[ep] = conn;
            } else {
                connectionMapSslCtx_.erase(&conn->ssl_);
            }
        }
    }
}

/**
 * try to create a dtls connection. if using cookies and this is a
 * hello request, the context will not be created.
 */
DtlsConnectionImplPtr DtlsConnectionImpl::create(boost::asio::io_context& ioContext, DtlsServerImplPtr server, const boost::asio::ip::udp::endpoint& ep)
{
    std::stringstream connectionName;
    connectionName << ep << " <-> :" << server->getPort();
    auto conn = std::make_shared<DtlsConnectionImpl>(ioContext, server, ep, connectionName.str());
    if (conn->init(ep)) {
        return conn;
    }
    return nullptr;
}

DtlsConnectionImpl::DtlsConnectionImpl(boost::asio::io_context& ioContext, DtlsServerImplPtr server, const boost::asio::ip::udp::endpoint& ep, const std::string& connectionName)
    : io_(ioContext),
      server_(server),
      ep_(ep),
      timer_(ioContext),
      keepAlive_(ioContext, server->keepAliveSettings_),
      connectionName_(connectionName)
{
}

DtlsConnectionImpl::~DtlsConnectionImpl()
{
    mbedtls_ssl_free( &ssl_ );
}

bool DtlsConnectionImpl::init(const boost::asio::ip::udp::endpoint& ep)
{
    mbedtls_ssl_init( &ssl_ );

    int ret;

    if( ( ret = mbedtls_ssl_setup( &ssl_, &server_->conf_ ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return false;
    }

    auto self = shared_from_this();
    timer_.setCallback([self](){
            self->handleTimeout();
        });

    mbedtls_ssl_set_timer_cb( &ssl_, &timer_,
                              [](void* ctx, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds) {
                                  auto timer = reinterpret_cast<MbedTlsTimer*>(ctx);
                                  return timer->mbedSetTimer(intermediateMilliseconds, finalMilliseconds);
                              },
                              [](void* ctx) -> int {
                                  auto timer = reinterpret_cast<MbedTlsTimer*>(ctx);
                                  return timer->mbedGetTimer();
                              });

    mbedtls_ssl_session_reset( &ssl_ );

    if( ( ret = mbedtls_ssl_set_client_transport_id( &ssl_,
                                                     reinterpret_cast<const unsigned char*>(ep.data()), ep.size() ) ) != 0 )
    {
        printf( " failed\n  ! "
                "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret );
        return false;
    }

    mbedtls_ssl_set_bio( &ssl_, this,
                         &DtlsConnectionImpl::mbedSend, &DtlsConnectionImpl::mbedRecv, NULL );
    return true;
}


void DtlsConnectionImpl::handleTimeout()
{
    lib::span<const uint8_t> emptyPacket;

    if (state_ == COOKIE_VERIFY || state_ == HANDSHAKE) {
        handleHandshakePacket(emptyPacket);
    } else if (state_ == DATA) {
        handleDataPacket(emptyPacket);
    }
}

void DtlsConnectionImpl::handleHandshakePacket(lib::span<const uint8_t> packet) {
    int ret;
    recvBuffer_ = packet;
    ret = mbedtls_ssl_handshake( &ssl_ );
    recvBuffer_ = lib::span<uint8_t>();
    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        state_ = HANDSHAKE;
    }
    else if (ret == 0) {
        state_ = DATA;
        server_->connectionEnteredDataPhase(shared_from_this());
        startKeepAlive();
    }
    else {
        closeFromSelf();
        state_ = SERROR;
    }
}

void DtlsConnectionImpl::handleDataPacket(lib::span<const uint8_t> packet)
{
    int ret;
    std::array<uint8_t, 1500> buffer;
    recvBuffer_ = packet;
    ret = mbedtls_ssl_read( &ssl_, buffer.data(), buffer.size());
    recvBuffer_ = lib::span<uint8_t>();
    if (ret == 0) {
        // EOF
        closeFromSelf();
    } else if (ret > 0) {
        std::vector<uint8_t> data;
        std::copy(buffer.begin(), buffer.begin()+ret, std::back_inserter(data));
        uint8_t firstByte = data[0];
        dtlsRecvCount_++;
        auto received = lib::span<const uint8_t>(data.data(), data.size());
        if (KeepAlive::isKeepAliveRequest(received)) {
            auto keepAliveResponse = KeepAlive::createKeepAliveResponse(received);
            asyncSendApplicationData(lib::span<uint8_t>(keepAliveResponse->data(), keepAliveResponse->size()),[keepAliveResponse](const lib::error_code& /*ec*/){ });
        } else if (firstByte & 0x40) {
            // coap
            lib::span<const uint8_t> bufferView(buffer.data(), ret);
            server_->handleCoapPacket(shared_from_this(), bufferView);
        }
    } else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        // OK
    } else {
        closeFromSelf();
        state_ = SERROR;
    }
}

void DtlsConnectionImpl::dispatch(lib::span<const uint8_t> buffer)
{
    if (state_ == COOKIE_VERIFY || state_ == HANDSHAKE) {
        handleHandshakePacket(buffer);
    } else if (state_ == DATA) {
        if (buffer.size() > 0) {
            uint8_t firstByte = buffer.data()[0];
            if (firstByte == 240) {
                if (relayDataHandler_) {
                    relayDataHandler_(make_error_code(DtlsError::ok), buffer);
                }
            } else {
                handleDataPacket(buffer);
            }
        }
    }
}

void DtlsConnectionImpl::asyncSendApplicationData(lib::span<const uint8_t> data, DatagramSentHandler dsh)
{
    int ret;
    ret = mbedtls_ssl_write(&ssl_, data.data(), data.size());

    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // TODO packet too large
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // TODO should not be possible.
    } else if (ret < 0) {
        // TODO unknown error
    } else {
        dtlsSentCount_++;
        io_.post([dsh](){ dsh(make_error_code(DtlsError::ok)); });
        return;
    }
    io_.post([dsh](){ dsh(make_error_code(DtlsError::write_failed)); });
}

void DtlsConnectionImpl::asyncSendRelayPacket(lib::span<const uint8_t> packet, DatagramSentHandler dsh)
{
    server_->udpServer_.asyncSend(packet, ep_, [dsh](const boost::system::error_code& ec) {
            dsh(ec);
        });
}

void DtlsConnectionImpl::asyncClose(std::function<void (const lib::error_code& ec)> cb)
{
    if (state_ > DATA) {
        io_.post(std::bind(cb, make_error_code(DtlsError::ok)));
    }
    relayDataHandler_ = nullptr;
    mbedtls_ssl_close_notify(&ssl_);
    closeFromSelf();
    io_.post(std::bind(cb, make_error_code(DtlsError::ok)));
}

void DtlsConnectionImpl::closeFromSelf()
{
    state_ = CLOSED;
    keepAlive_.stop();
    timer_.cancel();
    mbedtls_ssl_session_reset(&ssl_);
    relayDataHandler_ = nullptr;
    server_->connectionClosed(shared_from_this());
}

void DtlsConnectionImpl::stopFromManager()
{
    // the manager has removed the connection, just close down.
    state_ = CLOSED;
    keepAlive_.stop();
    timer_.cancel();
    mbedtls_ssl_session_reset(&ssl_);
    relayDataHandler_ = nullptr;
}

void DtlsConnectionImpl::startKeepAlive()
{
    auto self = shared_from_this();
    keepAlive_.asyncWaitSendKeepAlive([self](const lib::error_code& ec){
            if (ec) {
                // someone closed the connection
                return;
            } else {
                KeepAlive::Action action = self->keepAlive_.shouldSendKeepAlive(self->dtlsRecvCount_, self->dtlsSentCount_);
                switch(action) {
                    case KeepAlive::KA_STOPPED:
                        return;
                    case KeepAlive::DO_NOTHING:
                        self->startKeepAlive();
                        break;
                    case KeepAlive::SEND_KA:
                    {
                        auto keepAlivePacket = KeepAlive::createKeepAliveRequest(self->keepAliveCount_);
                        self->asyncSendApplicationData(*keepAlivePacket, [self, keepAlivePacket](const lib::error_code& ec){
                                if (ec) {
                                    return; // return stop ka loop
                                } else {
                                    self->startKeepAlive();
                                    self->keepAliveCount_++;
                                }
                            });
                    }
                    break;
                    case KeepAlive::KA_TIMEOUT:
                        self->closeFromSelf();
                        break;
                }
            }
        });
}

std::string DtlsConnectionImpl::getAlpnProtocol()
{
    const char* alpn = mbedtls_ssl_get_alpn_protocol(&ssl_);
    if (alpn == NULL) {
        return "";
    } else {
        return std::string(alpn);
    }
}

lib::optional<std::array<uint8_t, 32> > DtlsConnectionImpl::getOtherPeerFingerprint()
{
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_);
    if (!crt) {
        return lib::nullopt;
    }
    return getFingerprintFromPeer(crt);
}

void DtlsConnectionImpl::accessDenied()
{
    mbedtls_ssl_send_alert_message(&ssl_, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED);
    closeFromSelf();
}

void DtlsConnectionImpl::asyncSend(std::shared_ptr<std::vector<uint8_t> > data)
{
    server_->udpServer_.asyncSend(*data, ep_, [data](const boost::system::error_code& /*ec*/){

        });
}

int DtlsConnectionImpl::mbedSend(void* ctx, const unsigned char* buffer, size_t bufferSize)
{
    auto con = reinterpret_cast<DtlsConnectionImpl*>(ctx);
    auto sendData = std::make_shared<std::vector<uint8_t> >();
    std::copy(buffer, buffer+bufferSize, std::back_inserter(*sendData));
    con->asyncSend(sendData);
    return (int)bufferSize;
}

int DtlsConnectionImpl::mbedRecv(void* ctx, unsigned char* buffer, size_t bufferSize)
{
    auto con = reinterpret_cast<DtlsConnectionImpl*>(ctx);
    if (!con->recvBuffer_.empty()) {
        size_t maxCopy = std::min(bufferSize, con->recvBuffer_.size());
        memcpy(buffer, con->recvBuffer_.data(), maxCopy);
        con->recvBuffer_ = lib::span<uint8_t>();
        return (int)maxCopy;
    } else {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
}

} // namespace
