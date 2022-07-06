#pragma once

#include "attach_server.hpp"
#include <util/io_service.hpp>

namespace nabto {
namespace test {

class BasestationFixture {
 public:
    BasestationFixture()
        : ioService_(nabto::IoService::create("basestationFixture")), attachServer_(nabto::test::AttachServer::create(ioService_->getIoService()))
    {
    }
    ~BasestationFixture()
    {
        attachServer_->stop();
    }
    std::string getRootCerts() {
        return attachServer_->getRootCerts();
    }
    std::string getHostname() {
        return attachServer_->getHostname();
    }
    uint16_t getPort() {
        return attachServer_->getPort();
    }
    void dropNthPacket(int n) { return attachServer_->dropNthPacket(n); }

 private:
    nabto::IoServicePtr ioService_;
    std::shared_ptr<nabto::test::AttachServer> attachServer_;
};


} } // namespace
