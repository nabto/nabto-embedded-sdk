#ifndef _NM_UNIX_LOGGING_H_
#define _NM_UNIX_LOGGING_H_

#include <stdarg.h>
#include <platform/np_logging.h>

void nm_unix_log_init();

void nm_unix_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
void nm_unix_log_buf(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len);


#endif //NM_UNIX_LOGGING_H_
