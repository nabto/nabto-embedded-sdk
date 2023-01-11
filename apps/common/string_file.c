#include "string_file.h"

#include <modules/file/nm_file.h>

#include <stdlib.h>


bool string_file_exists(struct nm_file* file, const char* fileName)
{
    return (file->exists(file->impl, fileName) == NM_FILE_OK);
}

bool string_file_load(struct nm_file* file, const char* fileName, char** content)
{
    size_t fileSize;
    enum nm_file_error ec = file->size(file->impl, fileName, &fileSize);
    if (ec != NM_FILE_OK) {
        return false;
    }
    char* output = calloc(1, fileSize+1);
    if (output == NULL) {
        return false;
    }

    size_t readLength;
    ec = file->read_file(file->impl, fileName, output, fileSize+1, &readLength);
    if (ec != NM_FILE_OK) {
        free(output);
        return false;
    }
    *content = output;
    return true;
}

bool string_file_save(struct nm_file* file, const char* fileName, char* content)
{
    size_t l = strlen(content);
    enum nm_file_error ec = file->write_file(file->impl, fileName, content, l);
    if (ec != NM_FILE_OK) {
        return false;
    }
    return true;
}
