#include "string_file.h"

#include <stdio.h>

#ifdef HAVE_UNISTD_H
// close on unix
#include <unistd.h>
#endif

#ifdef HAVE_IO_H
// close on windows
#include <io.h>
#endif

#include <stdlib.h>
#include <string.h>

bool string_file_exists(const char* fileName)
{
#ifdef HAVE_IO_H
    return (_access( fileName, 0 ) != -1 );
#else
    return (access( fileName, F_OK ) != -1 );
#endif
}

static bool load_from_file(FILE* f, char** out)
{
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        return false;
    }

    char* content = malloc(fsize + 1);
    if (content == NULL) {
        return false;
    }

    size_t read = fread(content, 1, fsize, f);
    if (read != (size_t)fsize) {
        free(content);
        return false;
    }

    content[fsize] = 0;
    *out = content;
    return true;
}

bool string_file_load(const char* fileName, char** content)
{
    FILE* f = fopen(fileName, "rb");
    if (f == NULL) {
        return false;
    }
    bool status = load_from_file(f, content);
    fclose(f);
    return status;
}

bool string_file_save(const char* fileName, char* content)
{
    bool status;

    FILE* f = fopen(fileName, "wb");
    if (f == NULL) {
        return false;
    }

    size_t contentSize = strlen(content);
    size_t written = fwrite(content, 1, contentSize, f);

    if (written != contentSize) {
        status = false;
    } else {
        status = true;
    }
    fclose(f);
    return status;
}
