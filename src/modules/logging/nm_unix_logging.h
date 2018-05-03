#ifndef _NM_UNIX_LOGGING_H_
#define _NM_UNIX_LOGGING_H_

#include <stdarg.h>

void nm_unix_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);


#endif //NM_UNIX_LOGGING_H_
