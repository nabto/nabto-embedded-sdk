#include "json_config.h"
#include "string_file.h"

#include <nn/log.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static const char* LOGM = "json_config";

bool json_config_exists(const char* fileName)
{
    if( access( fileName, F_OK ) != -1 ) {
        return true;
    } else {
        return false;
    }
}

static bool load_from_file(FILE* f, cJSON** config, struct nn_log* logger)
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
    if (*config == NULL) {
        const char* error = cJSON_GetErrorPtr();
        if (error != NULL) {
            NN_LOG_ERROR(logger, LOGM, "JSON parse error: %s", error);
        }
    }
    free(string);
    return (*config != NULL);
}

bool json_config_load(const char* fileName, cJSON** config, struct nn_log* logger)
{
    FILE* f = fopen(fileName, "rb");
    if (f == NULL) {
        NN_LOG_ERROR(logger, LOGM, "Cannot open file %s.", fileName);
        return false;
    }
    bool status = load_from_file(f, config, logger);
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

    j = cJSON_PrintUnformatted(config);
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
