#include "nm_api_logging.h"
#include <windows.h>

#define NM_WIN_LOGGING_FILE_LENGTH 24

void nm_api_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data)
{
    if(NABTO_LOG_SEVERITY_FILTER & msg->severity) {
        SYSTEMTIME st;
        GetSystemTime(&st);

        size_t fileLen = strlen(msg->file);
        char fileTmp[NM_WIN_LOGGING_FILE_LENGTH+4];
        if(fileLen > NM_WIN_LOGGING_FILE_LENGTH) {
            strcpy(fileTmp, "...");
            strcpy(fileTmp + 3, msg->file + fileLen - NM_WIN_LOGGING_FILE_LENGTH);
        } else {
            strcpy(fileTmp, msg->file);
        }
        char level[6];
        switch(msg->severity) {
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
        }

        printf("%02u:%02u:%02u:%03u %s(%03u)[%s] %s\n",
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               fileTmp, msg->line, level, msg->message);
    }

}
