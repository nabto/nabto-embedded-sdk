#ifndef _NABTO_LOGGING_H_
#define _NABTO_LOGGING_H_

#include <platform/nabto_logging_defines.h>
#include <nabto_types.h>
#include <stdarg.h>

void nabto_default_log(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);

struct nabto_logging {
    void (*log)(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
};

extern struct nabto_logging nabto_log;

#ifdef HAS_NO_VARIADIC_MACROS
void info_adapter(uint32_t module, const char* fmt, ...);
#else
void info_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
#endif

#ifndef NABTO_LOG_SEVERITY_FILTER
#define NABTO_LOG_SEVERITY_FILTER     NABTO_LOG_SEVERITY_LEVEL_INFO
#endif

#ifndef NABTO_LOG_INFO
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_INFO info_adapter
#  else
#    define NABTO_LOG_INFO(module, fmt, ...) info_adapter(NABTO_LOG_SEVERITY_INFO, module, __LINE__, __FILE__, fmt, __VA_ARGS__);
#  endif
#endif


#ifndef HEST
#define HEST 1
#endif



#endif//_NABTO_LOGGING_H_
