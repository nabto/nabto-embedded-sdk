#ifndef STRING_FILE_H_
#define STRING_FILE_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_fs;

// file with string content functions
bool string_file_exists(struct nm_fs* file, const char* fileName);
bool string_file_load(struct nm_fs* file, const char* fileName, char** content);
bool string_file_save(struct nm_fs* file, const char* fileName, char* content);

#ifdef __cplusplus
} // extern c
#endif

#endif
