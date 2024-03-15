#include "prompt_stdin.h"
#include <stdarg.h>
#include <ctype.h>


static void to_lowercase(char* buffer, size_t size)
{
    for (int i = 0; i < size && buffer[i] != 0; i++) {
        buffer[i] = (char)tolower(buffer[i]);
    }
}

static bool str_is_numerical(char* buffer, size_t size)
{
    for (int i = 0; i < size && buffer[i] != 0; i++) {
        char c = buffer[i];
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

static inline bool is_printable(char c)
{
    return c >= 0x20 && c <= 0x7e;
}

bool prompt(const char* msg, char* buffer, size_t bufferSize, ...)
{
    char c;
    int i = 0;
    int n = (int)bufferSize-1;

    va_list args;
    va_start(args, bufferSize);
    vprintf(msg, args);
    va_end(args);

    printf(": ");

    while ((c = (char)getchar())) {
        if (c == '\n' || c == EOF) {
            int nullBytePosition = i < n ? i : n;
            buffer[nullBytePosition] = 0;
            return i <= n;
        }

        if (i < n && is_printable(c)) {
            buffer[i] = c;
        }
        i++;
    }
    return false;
}

bool prompt_repeating(const char* msg, char* buffer, size_t bufferSize)
{
    while (true) {
        bool ret = prompt(msg, buffer, bufferSize);
        if (buffer[0] != 0) {
            return ret;
        }
    }
}


bool prompt_yes_no(const char* msg)
{
    while (true) {
        char buffer[4];
        char n = ARRAY_SIZE(buffer);

        bool valid;
        if (msg == NULL) {
            valid = prompt("[y/n]", buffer, n);
        } else {
            valid = prompt("%s [y/n]", buffer, n, msg);
        }

        if(!valid) {
            continue;
        }
        to_lowercase(buffer, n);

        if (strncmp(buffer, "y", n) == 0 || strncmp(buffer, "yes", n) == 0) {
            return true;
        }

        if (strncmp(buffer, "n", n) == 0 || strncmp(buffer, "no", n) == 0) {
            return false;
        }
    }
}


bool prompt_yes_no_default(const char* msg, bool def)
{
    while (true) {
        char buffer[4];
        char n = ARRAY_SIZE(buffer);

        bool valid;
        if (msg == NULL) {
            valid = prompt("(default: %s) [y/n]", buffer, n, def ? "y" : "n");
        } else {
            valid = prompt("%s (default: %s) [y/n]", buffer, n, msg, def ? "y" : "n");
        }

        if(!valid) {
            continue;
        }

        if (buffer[0] == 0) {
            return def;
        }

        to_lowercase(buffer, n);

        if (strncmp(buffer, "y", n) == 0 || strncmp(buffer, "yes", n) == 0) {
            return true;
        }

        if (strncmp(buffer, "n", n) == 0 || strncmp(buffer, "no", n) == 0) {
            return false;
        }
    }
}


uint16_t prompt_uint16(const char* msg, uint16_t max)
{
    while (true) {
        char buffer[16] = {0};
        int n = ARRAY_SIZE(buffer);

        bool valid;
        if (msg == NULL) {
            valid = prompt("[0-%d]", buffer, n, max);
        } else {
            valid = prompt("%s [0-%d]", buffer, n, msg, max);
        }

        if(!valid) {
            continue;
        }

        if (buffer[0] == 0) {
            continue;
        }

        if (!str_is_numerical(buffer, n)) {
            continue;
        }

        long num = strtol(buffer, NULL, 10);
        if (num <= max) {
            return (uint16_t)num;
        }
    }
}


uint16_t prompt_uint16_default(const char* msg, uint16_t max, uint16_t def)
{
    while (true) {
        char buffer[16] = {0};
        int n = ARRAY_SIZE(buffer);

        bool valid;
        if (msg == NULL) {
            valid = prompt("(default: %i) [0-%d]", buffer, n, def, max);
        } else {
            valid = prompt("%s (default: %i) [0-%d]", buffer, n, msg, def, max);
        }

        if(!valid) {
            continue;
        }

        if (buffer[0] == 0) {
            return def;
        }

        if (!str_is_numerical(buffer, n)) {
            continue;
        }

        long num = strtol(buffer, NULL, 10);
        if (num <= max) {
            return (uint16_t)num;
        }
    }
}
