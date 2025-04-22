#ifndef PROMPT_STDIN_H_
#define PROMPT_STDIN_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARRAY_SIZE(array) (sizeof(array)/sizeof((array)[0]))

bool prompt(const char* msg, char* buffer, size_t bufferSize, ...);
bool prompt_repeating(const char* msg, char* buffer, size_t bufferSize);
bool prompt_yes_no(const char* msg);
bool prompt_yes_no_default(const char* msg, bool def);
uint16_t prompt_uint16(const char* msg, uint16_t max);
uint16_t prompt_uint16_default(const char* msg, uint16_t max, uint16_t def);

#ifdef __cplusplus
} // extern c
#endif

#endif
