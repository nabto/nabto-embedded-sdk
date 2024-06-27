#include <boost/test/unit_test.hpp>

#include "iam_util.hpp"
#include "../spake2/spake2_util.hpp"
#include "../../util/helper.hpp"

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_user.h>

#include <iostream>
namespace nabto {
namespace test {

struct nn_log iamLogger;

void iam_logger(void* data, enum nn_log_severity severity, const char* module,
    const char* file, int line,
    const char* fmt, va_list args)
{
    (void)data; (void)module;
    const char* logLevelCStr = getenv("NABTO_LOG_LEVEL");
    if (logLevelCStr == NULL) { return; }
    std::string logLevelStr(logLevelCStr);
    if ((logLevelStr.compare("error") == 0 && severity <= NN_LOG_SEVERITY_ERROR) ||
        (logLevelStr.compare("warn") == 0 && severity <= NN_LOG_SEVERITY_WARN) ||
        (logLevelStr.compare("info") == 0 && severity <= NN_LOG_SEVERITY_INFO) ||
        (logLevelStr.compare("trace") == 0 && severity <= NN_LOG_SEVERITY_TRACE)
        ) {
        char log[256];
        int ret;

        ret = vsnprintf(log, 256, fmt, args);
        if (ret >= 256) {
            // The log line was too large for the array
        }
        size_t fileLen = strlen(file);
        char fileTmp[16 + 4];
        if (fileLen > 16) {
            strcpy(fileTmp, "...");
            strcpy(fileTmp + 3, file + fileLen - 16);
        }
        else {
            strcpy(fileTmp, file);
        }
        const char* level;
        switch (severity) {
        case NN_LOG_SEVERITY_ERROR:
            level = "ERROR";
            break;
        case NN_LOG_SEVERITY_WARN:
            level = "_WARN";
            break;
        case NN_LOG_SEVERITY_INFO:
            level = "_INFO";
            break;
        case NN_LOG_SEVERITY_TRACE:
            level = "TRACE";
            break;
        default:
            // should not happen as it would be caugth by the if
            level = "_NONE";
            break;
        }

        printf("%s(%03u)[%s] %s\n",
            fileTmp, line, level, log);

    }
}

NabtoDevice* buildIamTestDevice(std::string& confStr, std::string& stateStr, struct nm_iam* iam)
{
    NabtoDevice* d = nabto_device_new();
    iamLogger.logPrint = &nabto::test::iam_logger;

    char* key = NULL;
    nabto_device_create_private_key(d, &key);

    nabto_device_set_private_key(d, key);

    nabto_device_string_free(key);

    const char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        nabto_device_set_log_level(d, logLevel);
        nabto_device_set_log_std_out_callback(d);
    }
    nm_iam_init(iam, d, &iamLogger);

    struct nm_iam_configuration* conf = nm_iam_configuration_new();
    BOOST_TEST(nm_iam_serializer_configuration_load_json(conf, confStr.c_str(), NULL) == true);

    struct nm_iam_state* state = nm_iam_state_new();
    BOOST_TEST(nm_iam_serializer_state_load_json(state, stateStr.c_str(), NULL) == true);

    BOOST_TEST(nm_iam_load_configuration(iam, conf));
    BOOST_TEST(nm_iam_load_state(iam, state));

    return d;
}

IamVirtualConnTester::IamVirtualConnTester(std::string& confStr, std::string& stateStr)
{
    device_ = buildIamTestDevice(confStr, stateStr, &iam_);
    connection_ = nabto_device_virtual_connection_new(device_);

    ref_ = nabto_device_connection_get_connection_ref(connection_);
    future_ = nabto_device_future_new(device_);
}


IamVirtualConnTester::~IamVirtualConnTester()
{
    if (req_) {
        nabto_device_virtual_coap_request_free(req_);
    }
    nabto_device_virtual_connection_free(connection_);
    nabto_device_stop(device_);
    nabto_device_future_free(future_);
    nm_iam_deinit(&iam_);
    nabto_device_free(device_);
}

void IamVirtualConnTester::createCoapRequest(NabtoDeviceCoapMethod method, std::string path)
{
    if (req_) {
        nabto_device_virtual_coap_request_free(req_);
    }
    req_ = nabto_device_virtual_coap_request_new(connection_, method, path.c_str());
    BOOST_TEST((req_ != NULL));
}

void IamVirtualConnTester::setCborPayload(nlohmann::json& payload)
{
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req_, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);
    auto cborPl = nlohmann::json::to_cbor(payload);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req_, cborPl.data(), cborPl.size()) == NABTO_DEVICE_EC_OK);
}

void IamVirtualConnTester::setJsonPayload(nlohmann::json& payload)
{
    // TODO
}


void IamVirtualConnTester::executeCoap(uint16_t expectedStatus)
{
    nabto_device_virtual_coap_request_execute(req_, future_);
    NabtoDeviceError ec = nabto_device_future_wait(future_);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req_, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == expectedStatus);
    // TODO: save payload if one is returned
}

struct nm_iam_user* IamVirtualConnTester::findStateUser(std::string username)
{
    nm_iam_state* s = nm_iam_dump_state(&iam_);
    struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, username.c_str());
    if (usr == NULL) {
        nm_iam_state_free(s);
        return NULL;
    } else {
        auto ret = nm_iam_user_copy(usr);
        nm_iam_state_free(s);
        return ret;
    }
}


void IamVirtualConnTester::doPwdAuth(const std::string username, const std::string clientFp, const std::string pwd)
{
    nabto_device_virtual_connection_set_client_fingerprint(connection_, clientFp.c_str());

    char* devFp = NULL;
    nabto_device_get_device_fingerprint(device_, &devFp);
    BOOST_TEST((devFp != NULL));

    nabto_device_virtual_connection_set_device_fingerprint(connection_, devFp);

    const std::string deviceFp(devFp);
    nabto_device_string_free(devFp);

    const char* auth1Path = "/p2p/pwd-auth/1";
    const char* auth2Path = "/p2p/pwd-auth/2";

    uint8_t clientFpBin[32];
    uint8_t deviceFpBin[32];

    nabto::test::fromHex(clientFp, clientFpBin);
    nabto::test::fromHex(deviceFp, deviceFpBin);
    // SETUP
    nabto::test::Spake2Client cli(pwd, clientFpBin, deviceFpBin);
    std::vector<uint8_t> T;
    BOOST_TEST(cli.calculateT(T) == 0);

    // AUTH REQ 1
    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(connection_, NABTO_DEVICE_COAP_POST, auth1Path);

    BOOST_TEST((req != NULL));

    nlohmann::json root;
    root["Username"] = username;
    root["T"] = nlohmann::json::binary(T);

    auto payload = nlohmann::json::to_cbor(root);

    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(device_);

    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    // AUTH RESP 1
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    uint16_t cf;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);

    uint8_t* respPayload;
    size_t len;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(req, (void**)&respPayload, &len) == NABTO_DEVICE_EC_OK);


    BOOST_TEST(cli.calculateK(respPayload, len) == 0);
    BOOST_TEST(cli.calculateKey());
    std::array<uint8_t, 32> req2Key;
    BOOST_TEST(nabto::test::Spake2Client::sha256(cli.key_.data(), cli.key_.size(), req2Key.data()) == 0);

    std::array<uint8_t, 32> req2KeyHash;
    BOOST_TEST(nabto::test::Spake2Client::sha256(req2Key.data(), req2Key.size(), req2KeyHash.data()) == 0);

    nabto_device_virtual_coap_request_free(req);


    // AUTH REQ 2
    req = nabto_device_virtual_coap_request_new(connection_, NABTO_DEVICE_COAP_POST, auth2Path);

    BOOST_TEST((req != NULL));

    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, req2KeyHash.data(), req2KeyHash.size()) == NABTO_DEVICE_EC_OK);

    nabto_device_virtual_coap_request_execute(req, fut);

    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    // AUTH RESP 2
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    BOOST_TEST(nabto_device_virtual_coap_request_get_response_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);

    uint8_t* resp2Payload;
    size_t len2;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(req, (void**)&resp2Payload, &len2) == NABTO_DEVICE_EC_OK);

    BOOST_TEST(memcmp(resp2Payload, req2Key.data(), req2Key.size()) == 0);
    nabto_device_virtual_coap_request_free(req);
    nabto_device_future_free(fut);

}



}
} // namespaces

