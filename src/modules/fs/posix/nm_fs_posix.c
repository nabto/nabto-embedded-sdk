#include "../nm_fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#ifdef HAVE_IO_H
// close on windows
#include <io.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

#include "errno.h"

static enum nm_fs_error create_directory(void* impl, const char* path);
static enum nm_fs_error exists(void* impl, const char* path);
static enum nm_fs_error size(void* impl, const char* path, size_t* fileSize);
static enum nm_fs_error read_file(void* impl, const char* path, void* buffer, size_t bufferSize, size_t* readLength);
static enum nm_fs_error write_file(void* impl, const char* path, const uint8_t* content, size_t contentSize);

struct nm_fs nm_fs_posix_get_impl(void)
{
    struct nm_fs impl;
    impl.impl = NULL;
    impl.create_directory = create_directory;
    impl.file_exists = exists;
    impl.file_size = size;
    impl.read_file = read_file;
    impl.write_file = write_file;
    return impl;
}

static enum nm_fs_error create_directory(void* impl, const char* path)
{
    (void)impl;
#if defined(HAVE_DIRECT_H)
    _mkdir(path);
#else
    mkdir(path, 0777);
#endif
    return NM_FS_OK;
}

static enum nm_fs_error exists(void* impl, const char* path)
{
    (void)impl;
    int ec = 0;
#if defined(HAVE_IO_H)
    ec = _access( path, 0 );
#else
    ec = access( path, F_OK );
#endif
    if (ec == 0) {
        return NM_FS_OK;
    }
    return NM_FS_NO_ENTRY;
}

static enum nm_fs_error size(void* impl, const char* path, size_t* fileSize)
{
    (void)impl;
    FILE* f = fopen(path, "rb");
    enum nm_fs_error status = NM_FS_UNKNOWN;
    if (f == NULL) {
        if (errno == ENOENT) {
            return NM_FS_NO_ENTRY;
        }
        return NM_FS_UNKNOWN;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        status = NM_FS_UNKNOWN;
    } else {
        status = NM_FS_OK;
        *fileSize = fsize;
    }
    fclose(f);

    return status;
}

static enum nm_fs_error read_file(void* impl, const char* path, void* buffer, size_t bufferSize, size_t* readLength)
{
    (void)impl;
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        if (errno == ENOENT) {
            return NM_FS_NO_ENTRY;
        }
        return NM_FS_UNKNOWN;
    }

    enum nm_fs_error status = NM_FS_OK;

    size_t read = fread(buffer, 1, bufferSize, f);
    if (read < 0) {
        status = NM_FS_UNKNOWN;
    } else {
        *readLength = read;
    }

    fclose(f);

    return status;
}

#if defined(HAVE_UNISTD_H) && !defined(_WIN32)
// The file is written to a temporary file which is renamed over the target, so
// a crash or a full disk leaves the previous content intact. mkstemp creates the
// temporary file with mode 0600, so the file is never readable by other users,
// it can hold the private key of the device.
static enum nm_fs_error write_file(void* impl, const char* path, const uint8_t* content, size_t contentSize)
{
    (void)impl;
    static const char suffix[] = ".XXXXXX";
    size_t pathLength = strlen(path);
    char* tmpPath = (char*)malloc(pathLength + sizeof(suffix));
    if (tmpPath == NULL) {
        return NM_FS_UNKNOWN;
    }
    memcpy(tmpPath, path, pathLength);
    memcpy(tmpPath + pathLength, suffix, sizeof(suffix));

    int fd = mkstemp(tmpPath);
    if (fd < 0) {
        free(tmpPath);
        return NM_FS_UNKNOWN;
    }

    enum nm_fs_error status = NM_FS_OK;
    size_t written = 0;
    while (written < contentSize) {
        ssize_t n = write(fd, content + written, contentSize - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        written += (size_t)n;
    }
    if (written != contentSize) {
        status = NM_FS_TRUNCATED;
    } else if (fsync(fd) != 0) {
        status = NM_FS_UNKNOWN;
    }
    if (close(fd) != 0 && status == NM_FS_OK) {
        status = NM_FS_UNKNOWN;
    }

    if (status == NM_FS_OK && rename(tmpPath, path) != 0) {
        status = NM_FS_UNKNOWN;
    }
    if (status != NM_FS_OK) {
        unlink(tmpPath);
    }
    free(tmpPath);
    return status;
}
#else
static enum nm_fs_error write_file(void* impl, const char* path, const uint8_t* content, size_t contentSize)
{
    (void)impl;
    enum nm_fs_error status = NM_FS_OK;

    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        return NM_FS_UNKNOWN;
    }

    size_t written = fwrite(content, 1, contentSize, f);

    if (written != contentSize) {
        status = NM_FS_TRUNCATED;
    } else {
        status = NM_FS_OK;
    }
    fclose(f);
    return status;
}
#endif
