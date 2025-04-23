#include "nm_logging_test.h"

#include <platform/np_logging.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NM_UNIX_LOGGING_FILE_LENGTH 24

static void nm_test_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);

static uint32_t logLevel = NABTO_LOG_SEVERITY_LEVEL_NONE;

static int common_strcasecmp(const char* s1, const char* s2)
{
#if defined(_WIN32)
    return _stricmp(s1,s2);
#else
    return strcasecmp(s1,s2);
#endif
}

void nm_logging_test_init(void)
{
    np_log.log = &nm_test_log;

    char* logLevelStr = getenv("NABTO_LOG_LEVEL");
    if (logLevelStr) {

        if (common_strcasecmp(logLevelStr, "trace") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_TRACE;
        } else if (common_strcasecmp(logLevelStr, "info") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_INFO;
        } else if (common_strcasecmp(logLevelStr, "warn") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_WARN;
        } else if (common_strcasecmp(logLevelStr, "error") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_ERROR;
        } else {
            // invalid log level
        }

    }
}

void nm_test_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
    if(((logLevel & severity) && ((NABTO_LOG_MODULE_FILTER & module) || module == 0))) {

        size_t fileLen = strlen(file);
        //char fileTmp[NM_UNIX_LOGGING_FILE_LENGTH+4];
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

        printf("%s(%03u)[%s] ",
               fileTmp, line, level);
        vprintf(fmt, args);
        printf("\n");
    }
}
