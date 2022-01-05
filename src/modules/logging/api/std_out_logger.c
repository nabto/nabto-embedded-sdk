
#include <nabto/nabto_device.h>

#include <api/nabto_device_logging_std_out_callback.h>

#include <sys/time.h>
#include "time.h"
#include <stdio.h>


struct timestamp {
    int year; // e.g. 2022
    int month; // 1-12
    int day; // 1-31
    int hour; // 0-23
    int minute; // 0-59
    int seconds; // 0-60 if for whatever reason there is a leap second.
    int milliseconds; // 0-999
};


static struct timestamp getTimestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t now = time(NULL);
    struct tm currentTime;
    localtime_r(&now, &currentTime);

    struct timestamp ts;
    ts.seconds = currentTime.tm_sec;
    ts.minute = currentTime.tm_min;
    ts.hour = currentTime.tm_hour;
    ts.year = currentTime.tm_year;
    ts.month = currentTime.tm_mon;
    ts.day = currentTime.tm_mday;
    ts.milliseconds = tv.tv_usec/1000;
    return ts;
}



#define NM_API_LOGGING_FILE_LENGTH 24

void nabto_device_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data)
{

    struct timestamp ts = getTimestamp();

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

    printf("%04u-%02u-%02u %02u:%02u:%02u.%03u %s(%03u)[%s] %s\n",
           ts.year, ts.month, ts.day, ts.hour, ts.day, ts.minute, ts.milliseconds,
           fileTmp, msg->line, level, msg->message);
    fflush(stdout);
}
