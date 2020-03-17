#ifndef _STRING_FILE_H_
#define _STRING_FILE_H_

// file with string content functions

bool string_file_exists(const char* fileName);
bool string_file_load(const char* fileName, char** content);
bool string_file_save(const char* fileName, char* content);

#endif
