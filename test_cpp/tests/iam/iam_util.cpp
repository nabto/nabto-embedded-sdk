#include <boost/test/unit_test.hpp>

#include "iam_util.hpp"

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>

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

}
} // namespaces

