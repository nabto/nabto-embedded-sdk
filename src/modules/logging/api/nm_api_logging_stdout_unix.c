#include "nm_api_logging.h"

#include <time.h>
#include <sys/time.h>
#include <stdio.h>

#define NM_API_LOGGING_FILE_LENGTH 24

void nm_api_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data)
{
    // This if statement only works because NabtoDeviceLogLevel is defined the same way as the internal log levels
    if(NABTO_LOG_SEVERITY_FILTER & msg->severity) {
        time_t sec;
        unsigned int ms;
        struct timeval tv;
        struct tm tm;
        gettimeofday(&tv, NULL);
        sec = tv.tv_sec;
        ms = tv.tv_usec/1000;

        localtime_r(&sec, &tm);

        size_t fileLen = strlen(msg->file);
        char fileTmp[NM_API_LOGGING_FILE_LENGTH+4];
        if(fileLen > NM_API_LOGGING_FILE_LENGTH) {
            strcpy(fileTmp, "...");
            strcpy(fileTmp + 3, msg->file + fileLen - NM_API_LOGGING_FILE_LENGTH);
        } else {
            strcpy(fileTmp, msg->file);
        }
        char level[6];
        switch(msg->severity) {
            case NABTO_DEVICE_LOG_FATAL:
                strcpy(level, "FATAL");
                break;
            case NABTO_DEVICE_LOG_ERROR:
                strcpy(level, "ERROR");
                break;
            case NABTO_DEVICE_LOG_WARN:
                strcpy(level, "_WARN");
                break;
            case NABTO_DEVICE_LOG_INFO:
                strcpy(level, "_INFO");
                break;
            case NABTO_DEVICE_LOG_TRACE:
                strcpy(level, "TRACE");
                break;
            default:
                // should not happen as it would be caugth by the if
                strcpy(level, "_NONE");
                break;
        }

        printf("%02u:%02u:%02u:%03u %s(%03u)[%s] %s\n",
               tm.tm_hour, tm.tm_min, tm.tm_sec, ms,
               fileTmp, msg->line, level, msg->message);
    }
 
}
