#include <nabto/nabto_device_config.h>

#ifndef NABTO_DEVICE_NO_LOG_STD_OUT_CALLBACK

#include <nabto/nabto_device.h>

#include <api/nabto_device_logging_std_out_callback.h>

#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#elif defined(HAVE_WINDOWS_H)
#include <windows.h>
#endif
#include "time.h"
#include <stdio.h>


struct datetime {
    int year; // e.g. 2022
    int month; // 1-12
    int day; // 1-31
    int hour; // 0-23
    int minute; // 0-59
    int seconds; // 0-60 if for whatever reason there is a leap second.
    int milliseconds; // 0-999
};


static struct datetime getTimestamp() {
    struct datetime ts;
#if defined(HAVE_SYS_TIME_H)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts.milliseconds = tv.tv_usec/1000;
    time_t now = time(NULL);
    struct tm currentTime;
    localtime_r(&now, &currentTime);

    ts.seconds = currentTime.tm_sec;
    ts.minute = currentTime.tm_min;
    ts.hour = currentTime.tm_hour;
    ts.year = currentTime.tm_year + 1900;
    ts.month = currentTime.tm_mon + 1;
    ts.day = currentTime.tm_mday;

#elif defined(HAVE_WINDOWS_H)
    SYSTEMTIME st;
    GetSystemTime(&st);

    ts.seconds = st.wSecond;
    ts.minute = st.wMinute;
    ts.hour = st.wHour;
    ts.year = st.wYear;
    ts.month = st.wMonth;
    ts.day = st.wDay;
    ts.milliseconds = st.wMilliseconds;
#else
    #error cannot get the current datetime
#endif
    return ts;
}



#define NM_API_LOGGING_FILE_LENGTH 24

void nabto_device_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data)
{

    struct datetime ts = getTimestamp();

    size_t fileLen = strlen(msg->file);
    const char* fileTmp = msg->file;

    if(fileLen > NM_API_LOGGING_FILE_LENGTH) {
        fileTmp = msg->file + fileLen - NM_API_LOGGING_FILE_LENGTH;
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
           ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.seconds, ts.milliseconds,
           fileTmp, msg->line, level, msg->message);
    fflush(stdout);
}
#endif
