#include "../nm_file.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#ifdef HAVE_IO_H
// close on windows
#include <io.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

#include "errno.h"

static enum nm_file_error create_directory(void* impl, const char* path);
static enum nm_file_error exists(void* impl, const char* path);
static enum nm_file_error size(void* impl, const char* path, size_t* fileSize);
static enum nm_file_error read_file(void* impl, const char* path, void* buffer, size_t bufferSize, size_t* readLength);
static enum nm_file_error write_file(void* impl, const char* path, const uint8_t* content, size_t contentSize);

struct nm_file nm_file_unix_get_impl()
{
    struct nm_file impl;
    impl.impl = NULL;
    impl.create_directory = create_directory;
    impl.exists = exists;
    impl.size = size;
    impl.read_file = read_file;
    impl.write_file = write_file;
    return impl;
};

static enum nm_file_error create_directory(void* impl, const char* path)
{
#if defined(_WIN32)
    _mkdir(path);
#else
    mkdir(path, 0777);
#endif
    return NM_FILE_OK;
}

static enum nm_file_error exists(void* impl, const char* path)
{
#if defined(HAVE_IO_H)
    return (_access( path, 0 ) != -1 );
#else
    return (access( path, F_OK ) != -1 );
#endif
}

static enum nm_file_error size(void* impl, const char* path, size_t* fileSize)
{
    FILE* f = fopen(path, "rb");
    enum nm_file_error status;
    if (f == NULL) {
        if (errno == ENOENT) {
            return NM_FILE_NO_ENTRY;
        } else {
            return NM_FILE_UNKNOWN;
        }
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        status = NM_FILE_UNKNOWN;
    } else {
        status = NM_FILE_OK;
        *fileSize = fsize;
    }
    fclose(f);

    return status;
}

static enum nm_file_error read_file(void* impl, const char* path, void* buffer, size_t bufferSize, size_t* readLength)
{
   FILE* f = fopen(path, "rb");
    if (f == NULL) {
        if (errno == ENOENT) {
            return NM_FILE_NO_ENTRY;
        } else {
            return NM_FILE_UNKNOWN;
        }
    }

    enum nm_file_error status = NM_FILE_OK;

    size_t read = fread(buffer, 1, bufferSize, f);
    if (read < 0) {
        status = NM_FILE_UNKNOWN;
    } else {
        *readLength = read;
    }

    fclose(f);

    return status;
}

static enum nm_file_error write_file(void* impl, const char* path, const uint8_t* content, size_t contentSize)
{
    enum nm_file_error status = NM_FILE_OK;

    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        return NM_FILE_UNKNOWN;
    }

    size_t written = fwrite(content, 1, contentSize, f);

    if (written != contentSize) {
        status = NM_FILE_TRUNCATED;
    } else {
        status = NM_FILE_OK;
    }
    fclose(f);
    return status;
}
