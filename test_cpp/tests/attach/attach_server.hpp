#pragma once

#include <fixtures/dtls_server/dtls_server.hpp>
#include <boost/asio/io_service.hpp>
//#include <util/test_future.hpp>
#include <fixtures/dtls_server/mbedtls_util.hpp>

#include <nlohmann/json.hpp>

#include <cbor.h>
#include <future>

namespace nabto {
namespace test {

static std::string privateKey = R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMdRmzNQrp+WRBwt9WXxZQSqe+ZQEtEuAQRZqwuB8nX9oAoGCCqGSM49
AwEHoUQDQgAEShTBGm7dCj1JBJHF82g53jeaz2afIlktXYqHy1FcUzTeV7c9+Lk7
W0AlwL/AcMp+rBJbjFaCdG7NYjNKhK0Atw==
-----END EC PRIVATE KEY-----
)";

static std::string certChain = R"(-----BEGIN CERTIFICATE-----
MIIBcjCCARkCFHgBfGhVNbsaSoZeagEOtzZFSQBqMAoGCCqGSM49BAMCMDgxCzAJ
BgNVBAYTAkRLMQ0wCwYDVQQKDARUZXN0MRowGAYDVQQDDBFUZXN0IEludGVybWVk
aWF0ZTAeFw0yMDEwMDYxMzQzNDlaFw0yMjEyMTUxMzQzNDlaMEAxCzAJBgNVBAYT
AkRLMQ0wCwYDVQQKDARUZXN0MSIwIAYDVQQDDBlsb2NhbGhvc3QtbXVsdGkubmFi
dG8ubmV0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEShTBGm7dCj1JBJHF82g5
3jeaz2afIlktXYqHy1FcUzTeV7c9+Lk7W0AlwL/AcMp+rBJbjFaCdG7NYjNKhK0A
tzAKBggqhkjOPQQDAgNHADBEAiB5m5zntsiAW7G+heAwPZJYdlPxarzlDgHSEOZY
7EMuXQIgC8+2s4VAwdeBYtqQlIihXonTDxa7w4Mzhm+T/rKThIc=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB0DCCAXagAwIBAgIUDt0M/PE8dqdWT7ru86Bl4Ff8kh0wCgYIKoZIzj0EAwIw
MDELMAkGA1UEBhMCREsxDTALBgNVBAoMBFRlc3QxEjAQBgNVBAMMCVRlc3QgUm9v
dDAeFw0yMDEwMDUxOTE5MTJaFw0yMzEwMDUxOTE5MTJaMDgxCzAJBgNVBAYTAkRL
MQ0wCwYDVQQKDARUZXN0MRowGAYDVQQDDBFUZXN0IEludGVybWVkaWF0ZTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABB/ceDZO2PN7gT5TuggLGXbS96jJ/orkTgXX
MsQ8E+aImQDyKhHC9cWhwclKso7gyQIeAcqiyMrpDBnqKgktjfijZjBkMB0GA1Ud
DgQWBBT3JkWHFo2+s0tr+kiy+00penDxDTAfBgNVHSMEGDAWgBRyog+DI9u8+S/g
kI1n8CXfJdO8jjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAK
BggqhkjOPQQDAgNIADBFAiEAmw9lGNV7DWqVkp0T2xh9xKiLSaBu361DQydrZvng
R5ICIGv8BpMSs5QYJ6T03+5ZS3A0sVGcnEsUPmcK3XWi4CTl
-----END CERTIFICATE-----
)";

static std::string rootCerts = R"(-----BEGIN CERTIFICATE-----
MIIBpTCCAUqgAwIBAgIUev5miQGPmjlHmisQJ5iYiq+Lf0kwCgYIKoZIzj0EAwIw
MDELMAkGA1UEBhMCREsxDTALBgNVBAoMBFRlc3QxEjAQBgNVBAMMCVRlc3QgUm9v
dDAeFw0yMDA2MjAwMDAwMDBaFw00OTEyMzEyMzU5NTlaMDAxCzAJBgNVBAYTAkRL
MQ0wCwYDVQQKDARUZXN0MRIwEAYDVQQDDAlUZXN0IFJvb3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATWs9bVLhO8o+42UrDFZocbMjvt20ODDwjxjC5/lSKo8KU6
yPcBsI6IMg+CfMfQpza7V5m9c/mHXw1r8iiOrizio0IwQDAdBgNVHQ4EFgQUcqIP
gyPbvPkv4JCNZ/Al3yXTvI4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwCgYIKoZIzj0EAwIDSQAwRgIhAKjXktlBZjxURdyDvlvPUn73cNz8MOTs7wl3
ogsvei0AAiEA4r6s8iI6b37agG6zXsPKXwjTw3jS4acs1feiZ4Vo1NE=
-----END CERTIFICATE-----
)";

static std::string serverHostname = "localhost-multi.nabto.net";
class AttachCoapServer {
 public:
    AttachCoapServer(boost::asio::io_context& io)
        : io_(io), dtlsServer_(io)
    {
    }

    AttachCoapServer(boost::asio::io_context& io, std::string ip, uint16_t port)
        : io_(io), dtlsServer_(io, ip)
    {
        port_ = port;
    }

    virtual ~AttachCoapServer() {}

    void init() {
        lib::error_code ec;
        dtlsServer_.setPort(port_);
        dtlsServer_.setAlpnProtocols({"n5"});
        dtlsServer_.setSniCallback([](const std::string& sni){
                (void)sni;
                return DtlsServer::createCertificateContext(privateKey, certChain);
            });

        ec = dtlsServer_.init();
        initCoapHandlers();
    }

    void stop() {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        std::future<void> future = promise_.get_future();
        io_.post([this](){
                     dtlsServer_.stop();
                     promise_.set_value();
                 });
        future.get();
    }

    virtual void initCoapHandlers() = 0;

    uint16_t getPort()
    {
        return dtlsServer_.getPort();
    }

    std::string getHostname() {
        return serverHostname;
    }

    std::string getRootCerts() {
        return rootCerts;
    }

    std::array<uint8_t, 16> getFingerprint()
    {
        auto fp = getFingerprintFromPem(certChain);
        std::array<uint8_t, 16> ret;
        memcpy(ret.data(), fp->data(), 16);
        return ret;
    }
 protected:
    boost::asio::io_context& io_;
    DtlsServer dtlsServer_;
    uint16_t port_ = 0;
    std::promise<void> promise_;
    bool stopped_ = false;

};

static const std::string firebaseOkResponse = R"(
{
    "name": "foobar"
}
)";

class AttachServer : public AttachCoapServer, public std::enable_shared_from_this<AttachServer>
{
 public:

    AttachServer(boost::asio::io_context& io)
        : AttachCoapServer(io)
    {
    }

    AttachServer(boost::asio::io_context& io, std::string ip, uint16_t port)
        : AttachCoapServer(io, ip, port)
    {
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<AttachServer>(io);
        ptr->init();
        return ptr;
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io, std::string ip, uint16_t port)
    {
        auto ptr = std::make_shared<AttachServer>(io, ip, port);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-start", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                if (self->attachCount_ == self->invalidAttach_) {
                    self->handleDeviceAttachWrongResponse(connection, request, response);
                } else {
                    self->handleDeviceAttach(connection, request, response);
                }
                self->attachCount_ += 1;
            });
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-end", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                (void)connection; (void)request;
                response->setCode(201);
                //self->attachCount_ += 1;
                return;
            });
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/fcm/send", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                (void)connection; (void)request;
                response->setCode(201);
                response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
                nlohmann::json root;
                root["StatusCode"] = 200;
                root["Body"] = firebaseOkResponse;
                std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
                response->setPayload(b);
                return;
            });
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/service/invoke", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                (void)connection; (void)request;
                response->setCode(201);
                response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
                nlohmann::json root;
                root["StatusCode"] = 200;
                std::string hw = "{\"hello\": \"world\"}";
                root["Message"] = nlohmann::json::binary_t(std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(hw.data()),reinterpret_cast<const uint8_t*>(hw.data()+ hw.size())));
                std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
                response->setPayload(b);
                return;
            });
    }

    void handleDeviceAttach(DtlsConnectionPtr connection,  std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection; (void)request;
        nlohmann::json root;
        root["Status"] = 0;
        nlohmann::json ka;
        ka["Interval"] = keepAliveInterval_;
        ka["RetryInterval"] = keepAliveRetryInterval_;
        ka["MaxRetries"] = keepAliveMaxRetries_;
        root["KeepAlive"] = ka;
        nlohmann::json stun;
        stun["Host"] = "stun.nabto.net";
        stun["Port"] = 3478;
        root["Stun"] = stun;

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(cbor);
        response->setCode(201);
    }

    void handleDeviceAttachWrongResponse(DtlsConnectionPtr connection,  std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection; (void)request;
        nlohmann::json root;
        root["FOOBAR"] = "BAZ";

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(cbor);
        response->setCode(201);
    }

    void setKeepAliveSettings(uint64_t interval, uint64_t retryInterval, uint64_t maxRetries)
    {
        keepAliveInterval_ = interval;
        keepAliveRetryInterval_ = retryInterval;
        keepAliveMaxRetries_ = maxRetries;
    }

    void niceClose() {
        dtlsServer_.asyncNiceClose([](const lib::error_code& ec){
                (void)ec;
                // all current connections is closed nicely.
            });
    }

    uint64_t keepAliveInterval_ = 30000;
    uint64_t keepAliveRetryInterval_ = 2000;
    uint64_t keepAliveMaxRetries_ = 15;

    std::atomic<uint64_t> attachCount_ = { 0 };
    uint64_t invalidAttach_ = 42;
};


class RedirectServer : public AttachCoapServer, public std::enable_shared_from_this<RedirectServer>
{
 public:

    RedirectServer(boost::asio::io_context& io)
        : AttachCoapServer(io)
    {
    }

    static std::shared_ptr<RedirectServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<RedirectServer>(io);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-start", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                (void)connection; (void)request;
                if (self->invalidRedirect_ == self->redirectCount_) {
                    self->handleDeviceRedirectInvalidResponse(connection, response);
                } else {
                    self->handleDeviceRedirect(connection, response);
                }
                self->redirectCount_++;
            });
    }

    void handleDeviceRedirectInvalidResponse(DtlsConnectionPtr connection, std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection;
        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setCode(201);
    }

    void handleDeviceRedirect(DtlsConnectionPtr connection, std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection;
        uint8_t buffer[128];

        CborEncoder encoder;
        CborEncoder map;
        cbor_encoder_init(&encoder, buffer, 128, 0);
        cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

        cbor_encode_text_stringz(&map, "Status");
        uint8_t redirect = 1;
        cbor_encode_uint(&map, redirect);

        cbor_encode_text_stringz(&map, "Host");
        cbor_encode_text_stringz(&map, host_.c_str());

        cbor_encode_text_stringz(&map, "Port");
        cbor_encode_uint(&map, port_);

        cbor_encode_text_stringz(&map, "Fingerprint");
        cbor_encode_byte_string(&map, fingerprint_.data(), fingerprint_.size());

        cbor_encoder_close_container(&encoder, &map);

        BOOST_TEST(cbor_encoder_get_extra_bytes_needed(&encoder) == (size_t)0);

        size_t length = cbor_encoder_get_buffer_size(&encoder, buffer);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(lib::span<const uint8_t>(buffer, length));
        response->setCode(201);
    }

    void setRedirect(const std::string& host, uint16_t port, std::array<uint8_t, 16> fingerprint)
    {
        host_ = host;
        port_ = port;
        fingerprint_ = fingerprint;
    }

    std::atomic<uint64_t> redirectCount_ = { 0 };

    // if the count matches this number send an invalid redirect
    uint64_t invalidRedirect_ = 42;
 private:
    std::string host_;
    uint16_t port_;
    std::array<uint8_t, 16> fingerprint_;


};

class AccessDeniedServer : public AttachCoapServer, public std::enable_shared_from_this<AccessDeniedServer>
{
 public:

    AccessDeniedServer(boost::asio::io_context& io)
        : AttachCoapServer(io)
    {
    }

    static std::shared_ptr<AccessDeniedServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<AccessDeniedServer>(io);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-start", [self](DtlsConnectionPtr connection,  std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                (void)response; (void)request;
                connection->accessDenied();
                self->coapRequestCount_++;
            });
    }

    std::atomic<uint64_t> coapRequestCount_ = { 0 };
};

} }
