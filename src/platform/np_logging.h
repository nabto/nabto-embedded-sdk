#ifndef _NP_LOGGING_H_
#define _NP_LOGGING_H_

#include <platform/np_logging_defines.h>
#include <nabto_types.h>
#include <stdarg.h>

void np_default_log(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);

struct np_logging {
    void (*log)(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
};

extern struct np_logging np_log;

#ifdef HAS_NO_VARIADIC_MACROS
void np_fatal_adapter(uint32_t module, const char* fmt, ...);
void np_error_adapter(uint32_t module, const char* fmt, ...);
void np_warn_adapter(uint32_t module, const char* fmt, ...);
void np_info_adapter(uint32_t module, const char* fmt, ...);
void np_debug_adapter(uint32_t module, const char* fmt, ...);
void np_trace_adapter(uint32_t module, const char* fmt, ...);
#else
#define VA_ARGS(...) , ##__VA_ARGS__
void np_fatal_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_error_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_warn_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_info_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_debug_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_trace_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
#endif

#ifndef NABTO_LOG_SEVERITY_FILTER
#define NABTO_LOG_SEVERITY_FILTER     NABTO_LOG_SEVERITY_LEVEL_INFO
#endif

#ifndef NABTO_LOG_FATAL
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_FATAL np_fatal_adapter
#  else
#    define NABTO_LOG_FATAL(module, fmt, ...) np_fatal_adapter(NABTO_LOG_SEVERITY_FATAL, module, __LINE__, __FILE__, fmt VA_ARGS(__VA_ARGS__));
#  endif
#endif

#ifndef NABTO_LOG_ERROR
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_ERROR np_error_adapter
#  else
#    define NABTO_LOG_ERROR(module, fmt, ...) np_error_adapter(NABTO_LOG_SEVERITY_ERROR, module, __LINE__, __FILE__, fmt VA_ARGS(__VA_ARGS__));
#  endif
#endif

#ifndef NABTO_LOG_WARN
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_WARN np_warn_adapter
#  else
#    define NABTO_LOG_WARN(module, fmt, ...) np_warn_adapter(NABTO_LOG_SEVERITY_WARN, module, __LINE__, __FILE__, fmt VA_ARGS(__VA_ARGS__));
#  endif
#endif

#ifndef NABTO_LOG_INFO
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_INFO np_info_adapter
#  else
#    define NABTO_LOG_INFO(module, fmt, ...) np_info_adapter(NABTO_LOG_SEVERITY_INFO, module, __LINE__, __FILE__, fmt VA_ARGS(__VA_ARGS__));
#  endif
#endif

#ifndef NABTO_LOG_DEBUG
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_DEBUG np_debug_adapter
#  else
#    define NABTO_LOG_DEBUG(module, fmt, ...) np_debug_adapter(NABTO_LOG_SEVERITY_DEBUG, module, __LINE__, __FILE__, fmt VA_ARGS(__VA_ARGS__));
#  endif
#endif

#ifndef NABTO_LOG_TRACE
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_TRACE np_trace_adapter
#  else
#    define NABTO_LOG_TRACE(module, fmt, ...) np_trace_adapter(NABTO_LOG_SEVERITY_TRACE, module, __LINE__, __FILE__, fmt VA_ARGS(__VA_ARGS__));
#  endif
#endif

#ifndef MAKE_IPV4_PRINTABLE
#define MAKE_IPV4_PRINTABLE(ip) (ip[0]), (ip[1]), (ip[2]), (ip[3])
#endif

#ifndef MAKE_IPV6_PRINTABLE
#define MAKE_IPV6_PRINTABLE(ip) (ip[0]), (ip[1]), (ip[2]), (ip[3]), (ip[4]), (ip[5]), (ip[6]), (ip[7]), (ip[8]), (ip[9]), (ip[10]), (ip[11]), (ip[12]), (ip[13]), (ip[14]), (ip[15])
#endif

#ifndef PRIip4
#define PRIip4 "%u.%u.%u.%u"
#endif

#ifndef PRIip6
#define PRIip6 "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x"
#endif



#endif//_NP_LOGGING_H_
