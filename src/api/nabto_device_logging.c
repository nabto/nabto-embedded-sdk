#include "nabto_device_logging.h"
#include <stdio.h>

#include <platform/np_platform.h>
//#include <platform/np_timestamp.h>

NabtoDeviceLogCallback logCallback;
void* userData;
static uint32_t level_ = NABTO_LOG_SEVERITY_LEVEL_INFO;

static void default_log_callback(NabtoDeviceLogMessage* msg, void* data)
{

}

static void logging_log(uint32_t severity, uint32_t module,
                        uint32_t line, const char* file,
                        const char* fmt, va_list args);

void nabto_device_logging_init()
{
    np_log.log = &logging_log;
    logCallback = &default_log_callback;
    userData = NULL;
}

void nabto_device_logging_set_level(uint32_t level)
{
    level_ = level;
}

void logging_log(uint32_t severity, uint32_t module,
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

void nabto_device_logging_set_callback(NabtoDeviceLogCallback cb, void* data)
{
    userData = data;
    logCallback = cb;
}

#define NM_API_LOGGING_FILE_LENGTH 24

void nabto_device_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data)
{

    struct np_platform* pl = data;
    uint32_t now = np_timestamp_now_ms(pl);

    uint32_t milliseconds = now%1000;
    uint32_t seconds = (now/1000)%1000;

    size_t fileLen = strlen(msg->file);
    char fileTmp[NM_API_LOGGING_FILE_LENGTH+4];
    if(fileLen > NM_API_LOGGING_FILE_LENGTH) {
        strcpy(fileTmp, "...");
        strcpy(fileTmp + 3, msg->file + fileLen - NM_API_LOGGING_FILE_LENGTH);
    } else {
        strcpy(fileTmp, msg->file);
    }
    const char* level;
    switch(msg->severity) {
        case NABTO_DEVICE_LOG_ERROR:
            level = "ERROR";
            break;
        case NABTO_DEVICE_LOG_WARN:
            level = "_WARN";
            break;
        case NABTO_DEVICE_LOG_INFO:
            level = "_INFO";
            break;
        case NABTO_DEVICE_LOG_TRACE:
            level = "TRACE";
            break;
        default:
            // should not happen as it would be caugth by the if
            level = "_NONE";
            break;
    }

    printf("%02u.%02u %s(%03u)[%s] %s\n",
           seconds, milliseconds,
           fileTmp, msg->line, level, msg->message);
}
