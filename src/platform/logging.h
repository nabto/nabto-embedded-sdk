#ifndef _NABTO_LOGGING_H_
#define _NABTO_LOGGING_H_

#include <platform/logging_defines.h>
#include <nabto_types.h>
#include <stdarg.h>

void nabto_default_log(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);

struct nabto_logging {
    void (*log)(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
};

extern struct nabto_logging nabto_log;

#ifdef HAS_NO_VARIADIC_MACROS
void nabto_fatal_adapter(uint32_t module, const char* fmt, ...);
void nabto_error_adapter(uint32_t module, const char* fmt, ...);
void nabto_warn_adapter(uint32_t module, const char* fmt, ...);
void nabto_info_adapter(uint32_t module, const char* fmt, ...);
void nabto_debug_adapter(uint32_t module, const char* fmt, ...);
void nabto_trace_adapter(uint32_t module, const char* fmt, ...);
#else
void nabto_fatal_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void nabto_error_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void nabto_warn_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void nabto_info_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void nabto_debug_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void nabto_trace_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
#endif

#ifndef NABTO_LOG_SEVERITY_FILTER
#define NABTO_LOG_SEVERITY_FILTER     NABTO_LOG_SEVERITY_LEVEL_INFO
#endif

#ifndef NABTO_LOG_FATAL
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_FATAL nabto_fatal_adapter
#  else
#    define NABTO_LOG_FATAL(module, fmt, ...) nabto_fatal_adapter(NABTO_LOG_SEVERITY_FATAL, module, __LINE__, __FILE__, fmt, __VA_ARGS__);
#  endif
#endif

#ifndef NABTO_LOG_ERROR
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_ERROR nabto_error_adapter
#  else
#    define NABTO_LOG_ERROR(module, fmt, ...) nabto_error_adapter(NABTO_LOG_SEVERITY_ERROR, module, __LINE__, __FILE__, fmt, __VA_ARGS__);
#  endif
#endif

#ifndef NABTO_LOG_WARN
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_WARN nabto_warn_adapter
#  else
#    define NABTO_LOG_WARN(module, fmt, ...) nabto_warn_adapter(NABTO_LOG_SEVERITY_WARN, module, __LINE__, __FILE__, fmt, __VA_ARGS__);
#  endif
#endif

#ifndef NABTO_LOG_INFO
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_INFO nabto_info_adapter
#  else
#    define NABTO_LOG_INFO(module, fmt, ...) nabto_info_adapter(NABTO_LOG_SEVERITY_INFO, module, __LINE__, __FILE__, fmt, __VA_ARGS__);
#  endif
#endif

#ifndef NABTO_LOG_DEBUG
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_DEBUG nabto_debug_adapter
#  else
#    define NABTO_LOG_DEBUG(module, fmt, ...) nabto_debug_adapter(NABTO_LOG_SEVERITY_DEBUG, module, __LINE__, __FILE__, fmt, __VA_ARGS__);
#  endif
#endif

#ifndef NABTO_LOG_TRACE
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_TRACE nabto_trace_adapter
#  else
#    define NABTO_LOG_TRACE(module, fmt, ...) nabto_trace_adapter(NABTO_LOG_SEVERITY_TRACE, module, __LINE__, __FILE__, fmt, __VA_ARGS__);
#  endif
#endif

#endif//_NABTO_LOGGING_H_
