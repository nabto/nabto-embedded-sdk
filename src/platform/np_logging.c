#include <platform/np_logging.h>

void np_default_log(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
}

struct np_logging np_log = { &np_default_log };

#ifdef HAS_NO_VARIADIC_MACROS
void np_error_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_ERROR, NABTO_LOG_MODULE_ALL, 0, "", fmt, args);
    va_end(args);
}
void np_warn_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_WARN, NABTO_LOG_MODULE_ALL, 0, "", fmt, args);
    va_end(args);
}
void np_info_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_INFO, NABTO_LOG_MODULE_ALL, 0, "", fmt, args);
    va_end(args);
}
void np_trace_adapter(uint32_t module, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    np_log.log(NABTO_LOG_SEVERITY_TRACE, NABTO_LOG_MODULE_ALL, 0, "", fmt, args);
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
