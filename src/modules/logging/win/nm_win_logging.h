#ifndef _NM_WIN_LOGGING_H_
#define _NM_WIN_LOGGING_H_

#include <stdarg.h>
#include <platform/np_logging.h>

void nm_win_log_init(void);

void nm_win_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args);
void nm_win_log_buf(uint32_t severity, uint32_t module, uint32_t line, const char* file, const uint8_t* buf, size_t len);


#endif //NM_WIN_LOGGING_H_
