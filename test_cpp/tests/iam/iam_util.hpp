#pragma once

#include <modules/iam/nm_iam.h>

#include <iostream>

namespace nabto {
namespace test {

static void iam_logger(void* data, enum nn_log_severity severity, const char* module,
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



}} // namespaces
