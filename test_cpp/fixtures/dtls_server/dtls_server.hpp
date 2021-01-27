#pragma once

#include <util/error_code.hpp>
#include <util/span.hpp>
#include <util/optional.hpp>

#include <boost/asio/io_context.hpp>

#include <fixtures/coap_server/coap_server.hpp>

#include "keep_alive.hpp"

namespace nabto {

class DtlsServerImpl;
class DtlsConnectionImpl;

class DtlsConnection {
 public:
    DtlsConnection() {};
    virtual ~DtlsConnection() {};
    typedef std::function<void (const lib::error_code& ec, lib::span<const uint8_t> data)> DatagramHandler;
    typedef std::function<void (const lib::error_code& ec)> DatagramSentHandler;

    virtual void setRelayPacketHandler(DatagramHandler dh) = 0;
    virtual void resetRelayPacketHandler() = 0;

    virtual void asyncSendApplicationData(lib::span<const uint8_t> data, DatagramSentHandler dsh) = 0;
    virtual std::string getAlpnProtocol() = 0;
    virtual lib::optional<std::array<uint8_t, 32> > getOtherPeerFingerprint() = 0;

    virtual void asyncSendRelayPacket(lib::span<const uint8_t> packet, DatagramSentHandler dsh) = 0;

    // send a Fatal Access denied.
    virtual void accessDenied() = 0;

};

class CoapServerRequest {
 public:
    virtual ~CoapServerRequest() {}
    virtual std::vector<uint8_t> getPayload() = 0;
    virtual int32_t getContentFormat() = 0;
    virtual std::string getParameter(const std::string& id) = 0;
};

class CoapServerResponse {
 public:
    virtual ~CoapServerResponse() {}
    virtual void setContentFormat(uint16_t contentFormat) = 0;
    virtual void setCode(uint16_t code) = 0;
    virtual void setPayload(lib::span<const uint8_t> payload) = 0;
};

typedef std::shared_ptr<DtlsConnection> DtlsConnectionPtr;

class CertificateContext;
typedef std::shared_ptr<CertificateContext> CertificateContextPtr;


class DtlsServer {
 public:
    DtlsServer(boost::asio::io_context& io);
    DtlsServer(boost::asio::io_context& io, std::string ip);
    ~DtlsServer();

    void stop();

    void asyncNiceClose(std::function<void (const lib::error_code& ec)> cb);

    void setPort(uint16_t port);
    uint16_t getPort();

    /**
     * override default keep alive settings.
     */
    void setKeepAliveSettings(KeepAliveSettings keepAliveSettings);

    /**
     * ovverride default handshake timeout settings
     */
    void setHandshakeTimeout(uint32_t min, uint32_t max);

    static std::shared_ptr<CertificateContext> createCertificateContext(const std::string& privateKey, const std::string& publicKey);

    typedef std::function<CertificateContextPtr (const std::string& sni)> SniCallback;

    // Called each time a connection is made.
    void setSniCallback(SniCallback cb);

    void setAlpnProtocols(std::vector<std::string> alpnProtocols);

    lib::error_code init();

    void addResourceHandler(nabto_coap_code method, const std::string& path, std::function<void (DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)> handler);

    void setConnectionClosedHandler(std::function<void (DtlsConnectionPtr connection)> cb);

 private:
    std::shared_ptr<DtlsServerImpl> impl_;
};

} // namespace
