#include "json_config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

bool json_config_exists(const char* fileName)
{
    if( access( fileName, F_OK ) != -1 ) {
        return true;
    } else {
        return false;
    }
}

static bool load_from_file(FILE* f, cJSON** config)
{
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *string = malloc(fsize + 1);
    if (string == NULL) {
        return false;
    }

    size_t read = fread(string, 1, fsize, f);
    if (read != fsize) {
        return false;
    }

    string[fsize] = 0;

    *config = cJSON_Parse(string);
    free(string);
    return (*config != NULL);
}

bool json_config_load(const char* fileName, cJSON** config)
{
    FILE* f = fopen(fileName, "rb");
    if (f == NULL) {
        return false;
    }
    bool status = load_from_file(f, config);
    fclose(f);
    return status;
}

bool json_config_save(const char* fileName, cJSON* config)
{
    bool status;
    char* j = NULL;

    FILE* f = fopen(fileName, "wb");
    if (f == NULL) {
        return false;
    }

    j = cJSON_Print(config);
    if (j == NULL) {
        status = false;
    } else {
        size_t jSize = strlen(j);
        size_t written = fwrite(j, 1, jSize, f);
        if (written != jSize) {
            status = false;
        } else {
            status = true;
        }
    }
    free(j);
    fclose(f);
    return status;
}
