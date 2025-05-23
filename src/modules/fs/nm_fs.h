#ifndef NM_FS_H_
#define NM_FS_H_

#include <stdint.h>
#include <string.h>

enum nm_fs_error {
    NM_FS_OK = 0,
    NM_FS_EXISTS,
    NM_FS_NO_ENTRY,
    NM_FS_TRUNCATED,
    NM_FS_UNKNOWN
};

struct nm_fs {
    void* impl;

    /**
     * Create a directory.
     * @retval NM_FS_OK iff ok
     * @retval NM_FS_EXISTS if the folder already exists
     */
    enum nm_fs_error (*create_directory)(void* impl, const char* path);

    /**
     * Query if a file exists
     * @retval NM_FS_OK
     * @retval NM_FS_NO_ENTRY
     */
    enum nm_fs_error (*file_exists)(void* impl, const char* path);

    /**
     * Get the size of a file
     * @retval NM_FS_OK iff ok
     * @retval NM_FS_NO_ENTRY if the file does not exists
     */
    enum nm_fs_error (*file_size)(void* impl, const char* path, size_t* fileSize);

    /**
     * Read a file
     *
     * @param impl the filesystem implementation
     * @param path the path
     * @param buffer the buffer for the content
     * @param bufferSize the size of the buffer
     * @param readLength The actual number of bytes read from the file
     * @retval NM_FS_OK iff ok
     * @retval NM_FS_NO_ENTRY if file not found.
     */
    enum nm_fs_error (*read_file)(void* impl, const char* path, void* buffer, size_t bufferSize, size_t* readLength);

    /**
     * Write a file
     *
     * @param impl the filesystem implementation
     * @param path the path
     * @param content the content
     * @param contentSize size of the content
     * @retval NM_FS_OK iff ok
     * @retval NM_FS_TRUNCATED if not all the content was written to the file
     */
    enum nm_fs_error (*write_file)(void* impl, const char* path, const uint8_t* content, size_t contentSize);
};

#endif
