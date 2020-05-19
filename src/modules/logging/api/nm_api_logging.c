#include "nm_api_logging.h"
#include <stdio.h>

NabtoDeviceLogCallback logCallback;
void* userData;
static uint32_t level_ = NABTO_LOG_SEVERITY_LEVEL_INFO;

void nm_api_log_default_log_callback(NabtoDeviceLogMessage* msg, void* data)
{

}

void nm_api_log(uint32_t severity, uint32_t module,
                uint32_t line, const char* file,
                const char* fmt, va_list args);

void nm_api_log_init()
{
    np_log.log = &nm_api_log;
    logCallback = &nm_api_log_default_log_callback;
    userData = NULL;
}

void nm_api_logging_set_level(uint32_t level)
{
    level_ = level;
}

void nm_api_log(uint32_t severity, uint32_t module,
                uint32_t line, const char* file,
                const char* fmt, va_list args)
{
    if (level_ & severity) {
        NabtoDeviceLogMessage msg;
        char log[256];
        int ret;

        ret = vsnprintf(log, 256, fmt, args);
        if (ret >= 256) {
            // TODO: handle too long log lines
            // The log line was too large for the array
        }

        switch(severity) {
            case NABTO_LOG_SEVERITY_ERROR:
                msg.severity = NABTO_DEVICE_LOG_ERROR;
                break;
            case NABTO_LOG_SEVERITY_WARN:
                msg.severity = NABTO_DEVICE_LOG_WARN;
                break;
            case NABTO_LOG_SEVERITY_INFO:
                msg.severity = NABTO_DEVICE_LOG_INFO;
                break;
            case NABTO_LOG_SEVERITY_TRACE:
                msg.severity = NABTO_DEVICE_LOG_TRACE;
                break;
            default:
                msg.severity = NABTO_DEVICE_LOG_ERROR;
                break;
        }

        msg.file = file;
        msg.line = line;
        msg.message = log;
        logCallback(&msg, userData);
    }
}

void nm_api_logging_set_callback(NabtoDeviceLogCallback cb, void* data)
{
    userData = data;
    logCallback = cb;
}
