#include "nm_logging_printf_time.h"

#if defined(HAVE_WINDOWS_H)
#include <windows.h>
#endif

#if defined(HAVE_SYS_TIME_H)
#include <time.h>
#include <sys/time.h>
#endif

void nm_logging_printf_time()
{
#if defined(HAVE_WINDOWS_H)
    SYSTEMTIME st;
    GetSystemTime(&st);

    printf("%02u:%02u:%02u:%03u",
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#elif defined(HAVE_SYS_TIME_H)
    time_t sec;
    unsigned int ms;
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    sec = tv.tv_sec;
    ms = tv.tv_usec/1000;

    localtime_r(&sec, &tm);
    printf("%02u:%02u:%02u.%03u", tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
#else
#error cannot print time
#endif
}
