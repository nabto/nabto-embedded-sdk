#include "nm_logging_test.h"

#include <platform/np_logging.h>

#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define NM_UNIX_LOGGING_FILE_LENGTH 24

static void nm_test_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
static void nm_test_log_buf(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len);

static uint32_t logLevel = NABTO_LOG_SEVERITY_LEVEL_NONE;

void nm_logging_test_init()
{
    np_log.log = &nm_test_log;
    np_log.log_buf = &nm_test_log_buf;

    char* logLevelStr = getenv("NABTO_LOG_LEVEL");
    if (logLevelStr) {

        if (strcasecmp(logLevelStr, "trace") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_TRACE;
        } else if (strcasecmp(logLevelStr, "info") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_INFO;
        } else if (strcasecmp(logLevelStr, "warn") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_WARN;
        } else if (strcasecmp(logLevelStr, "error") == 0) {
            logLevel = NABTO_LOG_SEVERITY_LEVEL_ERROR;
        } else {
            // invalid log level
        }

    }
}


void nm_test_log_buf(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len){
    if(!((logLevel & severity) &&
         ((NABTO_LOG_MODULE_FILTER & module) ||
          module == 0)))
    {
        return;
    }

    char str[128];
    char* ptr;
    size_t chunks = len/16;
    size_t i, n;
    int ret = 0;
    va_list list;

    for (i = 0; i < chunks; i++) {
        ret = sprintf(str, "%04lx: ", (long unsigned int)(i*16));
        ptr = str + ret;
        for (n = 0; n < 16; n++) {
            ret = sprintf(ptr, "%02x ", buf[i*16+n]);
            ptr = ptr + ret;
        }
        ret = sprintf(ptr, ": ");
        ptr = ptr + ret;

        for (n = 0; n < 16; n++) {
            if(buf[i*16+n] > 0x1F && buf[i*16+n] < 0x7F && buf[i*16+n] != 0x25) {
                ret = sprintf(ptr, "%c", (char)buf[i*16+n]);
                ptr = ptr + ret;
            } else {
                ret = sprintf(ptr, ".");
                ptr = ptr + ret;
            }
        }
        nm_test_log(severity, module, line, file, str, list);
    }
    ret = sprintf(str, "%04lx: ", (long unsigned int)(chunks*16));
    ptr = str + ret;
    for (n = chunks*16; n < len; n++) {
        ret = sprintf(ptr, "%02x ", buf[n]);
        ptr = ptr + ret;
    }
    for (; n < chunks*16+16; n++) {
        ret = sprintf(ptr, "   ");
        ptr = ptr + ret;
    }
    ret = sprintf(ptr, ": ");
    ptr = ptr + ret;

    for (n = chunks*16; n < len; n++) {
        if(buf[n] > 0x1F && buf[n] < 0x7F) {
            ret = sprintf(ptr, "%c", (char)buf[n]);
            ptr = ptr + ret;
        } else {
            ret = sprintf(ptr, ".");
            ptr = ptr + ret;
        }
    }
    nm_test_log(severity, module, line, file, str, list);
}

void nm_test_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
    if(((logLevel & severity) && ((NABTO_LOG_MODULE_FILTER & module) || module == 0))) {

        size_t fileLen = strlen(file);
        char fileTmp[NM_UNIX_LOGGING_FILE_LENGTH+4];
        if(fileLen > NM_UNIX_LOGGING_FILE_LENGTH) {
            strcpy(fileTmp, "...");
            strcpy(fileTmp + 3, file + fileLen - NM_UNIX_LOGGING_FILE_LENGTH);
        } else {
            strcpy(fileTmp, file);
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
        }

        printf("%s(%03u)[%s] ",
               fileTmp, line, level);
        vprintf(fmt, args);
        printf("\n");
    }
}
