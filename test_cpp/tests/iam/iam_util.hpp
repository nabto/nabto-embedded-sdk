#pragma once
#include <boost/test/unit_test.hpp>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <nabto/nabto_device_virtual.h>

#include <nlohmann/json.hpp>
#include <iostream>

namespace nabto {
namespace test {


void iam_logger(void* data, enum nn_log_severity severity, const char* module,
    const char* file, int line,
    const char* fmt, va_list args);

NabtoDevice* buildIamTestDevice(std::string& confStr, std::string& stateStr, struct nm_iam* iam);


class IamVirtualConnTester {
public:
    IamVirtualConnTester(std::string& confStr, std::string& stateStr);
    ~IamVirtualConnTester();

    void createCoapRequest(NabtoDeviceCoapMethod method, std::string path);

    void setCborPayload(nlohmann::json& payload);
    void setJsonPayload(nlohmann::json& payload);

    void executeCoap(uint16_t expectedStatus);

    struct nm_iam_user* findStateUser(std::string username);

    void doPwdAuth(const std::string username, const std::string clientFp, const std::string pwd);


    struct nm_iam iam_;
    NabtoDevice* device_;
    NabtoDeviceVirtualConnection* connection_;
    NabtoDeviceConnectionRef ref_;
    NabtoDeviceFuture* future_;
    NabtoDeviceVirtualCoapRequest* req_ = NULL;

};

}} // namespaces
