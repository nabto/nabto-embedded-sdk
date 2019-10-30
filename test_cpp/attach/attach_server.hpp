#pragma once

#include <dtls/dtls_server.hpp>
#include <boost/asio/io_service.hpp>
#include <util/logger.hpp>


namespace nabto {
namespace test {

class AttachServer : public std::enable_shared_from_this<AttachServer> {
 public:
    AttachServer(boost::asio::io_context& io, log::LoggerPtr logger)
        : io_(io), logger_(logger), dtlsServer_(io, logger)
    {
    }

 private:
    boost::asio::io_context& io_;
    log::LoggerPtr logger_;
    DtlsServer dtlsServer_;

};

} }
