#ifndef _STRING_FILE_H_
#define _STRING_FILE_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// file with string content functions
bool string_file_exists(const char* fileName);
bool string_file_load(const char* fileName, char** content);
bool string_file_save(const char* fileName, char* content);

#ifdef __cplusplus
} // extern c
#endif

#endif
