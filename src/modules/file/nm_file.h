#ifndef _NM_FILE_H_
#define _NM_FILE_H_

#include <string.h>
#include <stdint.h>

enum nm_file_error {
    NM_FILE_OK = 0,
    NM_FILE_EXISTS,
    NM_FILE_NO_ENTRY,
    NM_FILE_TRUNCATED,
    NM_FILE_UNKNOWN
};

struct nm_file {
    void* impl;

    /**
     * Create a directory.
     * @retval NM_FILE_OK iff ok
     * @retval NM_FILE_EXISTS if the folder already exists
     */
    enum nm_file_error (*create_directory)(void* impl, const char* path);

    /**
     * Query if a file exists
     * @retval NM_FILE_OK
     * @retval NM_FILE_NO_ENTRY
     */
    enum nm_file_error (*exists)(void* impl, const char* path);

    /**
     * Get the size of a file
     * @retval NM_FILE_OK iff ok
     * @retval NM_FILE_NO_ENTRY if the file does not exists
     */
    enum nm_file_error (*size)(void* impl, const char* path, size_t* fileSize);

    /**
     * Read a file
     *
     * @param impl the filesystem implementation
     * @param path the path
     * @param buffer the buffer for the content
     * @param bufferSize the size of the buffer
     * @param readLength The actual number of bytes read from the file
     * @retval NM_FILE_OK iff ok
     * @retval NM_FILE_NO_ENTRY if file not found.
     */
    enum nm_file_error (*read_file)(void* impl, const char* path, void* buffer, size_t bufferSize, size_t* readLength);

    /**
     * Write a file
     *
     * @param impl the filesystem implementation
     * @param path the path
     * @param content the content
     * @param contentSize size of the content
     * @retval NM_FILE_OK iff ok
     * @retval NM_FILE_TRUNCATED if not all the content was written to the file
     */
    enum nm_file_error (*write_file)(void* impl, const char* path, const uint8_t* content, size_t contentSize);
};

#endif
