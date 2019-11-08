#include <platform/np_logging.h>

void np_default_log(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
}
void np_default_log_buf(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len)
{
}
struct np_logging np_log = { &np_default_log, &np_default_log_buf };

#ifdef HAS_NO_VARIADIC_MACROS
void np_error_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_ERROR, "", 0, "", fmt, args);
    va_end(args);
}
void np_warn_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_WARN, "", 0, "", fmt, args);
    va_end(args);
}
void np_info_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_INFO, "", 0, "", fmt, args);
    va_end(args);
}
void np_trace_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_TRACE, "", 0, "", fmt, args);
    va_end(args);
}
#else
void np_error_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_ERROR, module, line, file, fmt, args);
    va_end(args);
}
void np_warn_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_WARN, module, line, file, fmt, args);
    va_end(args);
}
void np_info_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_INFO, module, line, file, fmt, args);
    va_end(args);
}
void np_trace_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_TRACE, module, line, file, fmt, args);
    va_end(args);
}
void np_raw_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(severity, module, line, file, fmt, args);
    va_end(args);
}
#endif

void np_buffer_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len)
{
    np_log.log_buf(NABTO_LOG_SEVERITY_TRACE, module, line, file, buf, len);
}
