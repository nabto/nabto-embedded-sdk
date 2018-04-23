#ifndef _NABTO_UNIX_LOGGING_H_
#define _NABTO_UNIX_LOGGING_H_

#include <stdarg.h>

void unix_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);


#endif //NABTO_UNIX_LOGGING_H_
