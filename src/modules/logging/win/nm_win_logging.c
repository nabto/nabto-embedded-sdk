
#include "nm_win_logging.h"
#include <nabto_types.h>

#include <windows.h>

#include <stdio.h>
#include <string.h>

#define NM_WIN_LOGGING_FILE_LENGTH 24

void np_log_init()
{
    np_log.log = &nm_win_log;
    np_log.log_buf = &nm_win_log_buf;
}

void nm_win_log_buf(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len){
    char str[128];
    char* ptr;
    size_t chunks = len/16;
    size_t i, n;
    int ret = 0;
    va_list list = NULL;
    
    for (i = 0; i < chunks; i++) {
        ret = sprintf(str, "%04lx: ", i*16);
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
        nm_win_log(severity, module, line, file, str, list);
    }
    ret = sprintf(str, "%04lx: ", chunks*16);
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
    nm_win_log(severity, module, line, file, str, list);
}

void nm_win_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
    if(((NABTO_LOG_SEVERITY_FILTER & severity) && ((NABTO_LOG_MODULE_FILTER & module) || module == 0))) {
        SYSTEMTIME st;
        GetSystemTime(&st);

        size_t fileLen = strlen(file);
        char fileTmp[NM_WIN_LOGGING_FILE_LENGTH+4];
        if(fileLen > NM_WIN_LOGGING_FILE_LENGTH) {
            strcpy(fileTmp, "...");
            strcpy(fileTmp + 3, file + fileLen - NM_WIN_LOGGING_FILE_LENGTH);
        } else {
            strcpy(fileTmp, file);
        }
        char level[6];
        switch(severity) {
            case NABTO_LOG_SEVERITY_FATAL:
                strcpy(level, "FATAL");
                break;
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

        printf("%02u:%02u:%02u:%03u %s(%03u)[%s] ",
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               fileTmp, line, level);
        vprintf(fmt, args);
        printf("\n");
    }
}
