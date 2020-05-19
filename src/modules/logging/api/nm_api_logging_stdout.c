#include "nm_api_logging.h"

#include <stdio.h>

#define NM_API_LOGGING_FILE_LENGTH 24

void nm_api_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data)
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
