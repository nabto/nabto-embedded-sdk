#include "dtls_server.hpp"

#include "dtls_server_impl.hpp"

#include "certificate_context.hpp"

namespace nabto {

DtlsServer::DtlsServer(boost::asio::io_context& io)
    : impl_(std::make_shared<DtlsServerImpl>(io))
{
}

DtlsServer::DtlsServer(boost::asio::io_context& io, std::string ip)
    : impl_(std::make_shared<DtlsServerImpl>(io, ip))
{

}

DtlsServer::~DtlsServer()
{
    impl_->stop();
}

void DtlsServer::stop() {
    impl_->stop();
}

void DtlsServer::asyncNiceClose(std::function<void (const lib::error_code& ec)> cb)
{
    impl_->asyncNiceClose(cb);
}


void DtlsServer::setPort(uint16_t port)
{
    impl_->setPort(port);
}
uint16_t DtlsServer::getPort()
{
    return impl_->getPort();
}

void DtlsServer::setKeepAliveSettings(KeepAliveSettings keepAliveSettings)
{
    return impl_->setKeepAliveSettings(keepAliveSettings);
}

void DtlsServer::setHandshakeTimeout(uint32_t min, uint32_t max)
{
    return impl_->setHandshakeTimeout(min, max);
}

lib::error_code DtlsServer::init()
{
    return impl_->init();
}

void DtlsServer::setAlpnProtocols(std::vector<std::string> alpnProtocols)
{
    impl_->setAlpnProtocols(alpnProtocols);
}

void DtlsServer::setSniCallback(SniCallback sniCallback)
{
    impl_->setSniCallback(sniCallback);
}

void DtlsServer::addResourceHandler(nabto_coap_code method, const std::string& path, std::function<void (DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)> handler)
{
    impl_->addResourceHandler(method, path, handler);
}

void DtlsServer::setConnectionClosedHandler(std::function<void (DtlsConnectionPtr connection)> cb)
{
    impl_->setConnectionClosedHandler(cb);
}

CertificateContextPtr DtlsServer::createCertificateContext(const std::string& privateKey, const std::string& publicKey)
{
    return CertificateContext::create(privateKey, publicKey);
}

CertificateContextPtr DtlsServer::createCertificateContext(const std::string& privateKey, const std::vector<std::string>& certificateChain)
{
    std::stringstream ss;
    for(auto cert : certificateChain) {
        ss << cert;
    }
    return CertificateContext::create(privateKey, ss.str());
}



} // namespace
