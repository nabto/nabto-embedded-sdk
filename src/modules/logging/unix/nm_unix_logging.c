
#include "nm_unix_logging.h"
#include <platform/np_types.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define NM_UNIX_LOGGING_FILE_LENGTH 24


static void nm_unix_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);

void nm_logging_unix_init()
{
    np_log.log = &nm_unix_log;
}

void nm_unix_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
    if(((NABTO_LOG_SEVERITY_FILTER & severity) && ((NABTO_LOG_MODULE_FILTER & module) || module == 0))) {
        time_t sec = 0;
        unsigned int ms = 0;
        struct timeval tv;
        struct tm tm;
        gettimeofday(&tv, NULL);
        sec = tv.tv_sec;
        ms = tv.tv_usec/1000;

        localtime_r(&sec, &tm);

        size_t fileLen = strlen(file);
        const char* fileTmp = file;
        if(fileLen > NM_UNIX_LOGGING_FILE_LENGTH) {
            fileTmp = file + fileLen - NM_UNIX_LOGGING_FILE_LENGTH;
        }
        char level[6];
        switch(severity) {
            case NABTO_LOG_SEVERITY_ERROR:
                strcpy(level, "ERROR");
                break;
            case NABTO_LOG_SEVERITY_WARN:
                strcpy(level, "_WARN");
                break;
            case NABTO_LOG_SEVERITY_INFO:
                strcpy(level, "_INFO");
                break;
            case NABTO_LOG_SEVERITY_TRACE:
                strcpy(level, "TRACE");
                break;
            default:
                strcpy(level, "TRACE");
        }

        printf("%02u:%02u:%02u:%03u %s(%03u)[%s] ",
               tm.tm_hour, tm.tm_min, tm.tm_sec, ms,
               fileTmp, line, level);
        vprintf(fmt, args);
        printf("\n");
    }
}
