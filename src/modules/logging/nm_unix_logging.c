
#include <nabto_types.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>

void nm_unix_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
    time_t sec;
    unsigned int ms;
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    sec = tv.tv_sec;
    ms = tv.tv_usec/1000;

    localtime_r(&sec, &tm);

    const char str[] = {"-sdk/"};
    while(strncmp(str, file, 5) != 0) {
        file++;
    }
    file = file + 5;
    printf("%02u:%02u:%02u:%03u %s(%u) ",
           tm.tm_hour, tm.tm_min, tm.tm_sec, ms,
           file, line);
    vprintf(fmt, args);
    printf("\n");
}
