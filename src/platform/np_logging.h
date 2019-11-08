#ifndef _NP_LOGGING_H_
#define _NP_LOGGING_H_

#include <platform/np_logging_defines.h>
#include <nabto_types.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

void np_log_init(void);

void np_default_log(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
void np_default_log_buf(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len);

struct np_logging {
    void (*log)(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
    void (*log_buf)(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len);
};

extern struct np_logging np_log;

#ifdef HAS_NO_VARIADIC_MACROS
void np_error_adapter(uint32_t module, const char* fmt, ...);
void np_warn_adapter(uint32_t module, const char* fmt, ...);
void np_info_adapter(uint32_t module, const char* fmt, ...);
void np_trace_adapter(uint32_t module, const char* fmt, ...);
#else
#define VA_ARGS(...) , ##__VA_ARGS__
void np_error_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_warn_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_info_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_trace_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
void np_raw_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...);
#endif
void np_buffer_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len);

//#define NABTO_LOG_MODULE_FILTER (NABTO_LOG_MODULE_RENDEZVOUS | NABTO_LOG_MODULE_CLIENT_CONNECT)

#ifndef NABTO_LOG_SEVERITY_FILTER
#define NABTO_LOG_SEVERITY_FILTER     NABTO_LOG_SEVERITY_LEVEL_INFO
//#define NABTO_LOG_SEVERITY_FILTER     NABTO_LOG_SEVERITY_LEVEL_TRACE
#endif

#ifndef NABTO_LOG_MODULE_FILTER
#define NABTO_LOG_MODULE_FILTER       NABTO_LOG_MODULE_ALL
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

#ifndef NABTO_LOG_TRACE
#  ifdef HAS_NO_VARADIC_MACROS
#    define NABTO_LOG_TRACE np_trace_adapter
#  else
#    define NABTO_LOG_TRACE(module, fmt, ...) np_trace_adapter(NABTO_LOG_SEVERITY_TRACE, module, __LINE__, __FILE__, fmt VA_ARGS(__VA_ARGS__));
#  endif
#endif

#ifndef NABTO_LOG_BUF
#    define NABTO_LOG_BUF(module, buf, len) np_buffer_adapter(NABTO_LOG_SEVERITY_TRACE, module, __LINE__, __FILE__, buf, len);
#endif

#ifndef NABTO_LOG_RAW
#  ifdef HAS_NO_VARADIC_MACROS
// RAW logging requires varadic macros
#    define NABTO_LOG_RAW
#  else
#    define NABTO_LOG_RAW(severity, module, line, file, fmt, ...) np_raw_adapter(severity, module, line, file, fmt VA_ARGS(__VA_ARGS__));
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

#ifdef __cplusplus
} //extern "C"
#endif

#endif//_NP_LOGGING_H_
