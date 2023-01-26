#include "json_config.h"
#include "string_file.h"

#include <nn/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* LOGM = "json_config";



bool json_config_exists(struct nm_file* fileImpl, const char* fileName)
{
    enum nm_file_error ec = fileImpl->exists(fileImpl->impl, fileName);
    if (ec == NM_FILE_OK) {
        return true;
    } else {
        return false;
    }
}

bool json_config_load(struct nm_file* fileImpl, const char* path, cJSON** config, struct nn_log* logger)
{
    size_t fileSize;
    enum nm_file_error ec = fileImpl->size(fileImpl->impl, path, &fileSize);
    if (ec != NM_FILE_OK) {
        return false;
    }

    uint8_t* buffer = calloc(1, fileSize+1);
    size_t readLength;
    ec = fileImpl->read_file(fileImpl->impl, path, buffer, fileSize+1, &readLength);
    if (ec != NM_FILE_OK) {
        free(buffer);
        return false;
    }

    if (readLength == fileSize + 1) {
        // read too much,
        free(buffer);
        return false;
    }

    *config = cJSON_Parse((const char*)buffer);
    if (*config == NULL) {
        const char* error = cJSON_GetErrorPtr();
        if (error != NULL) {
            NN_LOG_ERROR(logger, LOGM, "JSON parse error: %s", error);
        }
    }
    free(buffer);
    return (*config != NULL);
}

bool json_config_save(struct nm_file* fileImpl, const char* fileName, cJSON* config)
{
    bool status;
    char* j = NULL;

    j = cJSON_PrintUnformatted(config);
    if (j == NULL) {
        status = false;
    } else {
        size_t jSize = strlen(j);
        enum nm_file_error ec = fileImpl->write_file(fileImpl->impl, fileName, (const uint8_t*)j, jSize);
        if (ec == NM_FILE_OK) {
            status = true;
        } else {
            status = false;
        }
    }
    free(j);
    return status;
}
