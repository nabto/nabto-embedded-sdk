#include "string_file.h"

#include <modules/fs/nm_fs.h>

#include <stdlib.h>


bool string_file_exists(struct nm_fs* fsImpl, const char* fileName)
{
    return (fsImpl->file_exists(fsImpl->impl, fileName) == NM_FS_OK);
}

bool string_file_load(struct nm_fs* fsImpl, const char* fileName, char** content)
{
    size_t fileSize;
    enum nm_fs_error ec = fsImpl->file_size(fsImpl->impl, fileName, &fileSize);
    if (ec != NM_FS_OK) {
        return false;
    }
    char* output = calloc(1, fileSize+1);
    if (output == NULL) {
        return false;
    }

    size_t readLength;
    ec = fsImpl->read_file(fsImpl->impl, fileName, output, fileSize+1, &readLength);
    if (ec != NM_FS_OK) {
        free(output);
        return false;
    }
    *content = output;
    return true;
}

bool string_file_save(struct nm_fs* fsImpl, const char* fileName, char* content)
{
    size_t l = strlen(content);
    enum nm_fs_error ec = fsImpl->write_file(fsImpl->impl, fileName, (const uint8_t*)content, l);
    if (ec != NM_FS_OK) {
        return false;
    }
    return true;
}
