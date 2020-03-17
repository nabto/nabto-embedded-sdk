#include "string_file.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

bool string_file_exists(const char* fileName)
{
    if( access( fileName, F_OK ) != -1 ) {
        return true;
    } else {
        return false;
    }
}

static bool load_from_file(FILE* f, char** content)
{
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    *content = malloc(fsize + 1);
    if (*content == NULL) {
        return false;
    }

    size_t read = fread(*content, 1, fsize, f);
    if (read != fsize) {
        free(*content);
        return false;
    }

    *content[fsize] = 0;
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

bool json_config_save(const char* fileName, char* content)
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
