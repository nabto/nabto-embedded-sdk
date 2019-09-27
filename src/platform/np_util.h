#ifndef _NP_UTIL_H_
#define _NP_UTIL_H_

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Renamed MAX as NP_MAX, as it often gives problems with headers
// already defining MAX without testing for its existence and the
// header include order then becomes an issue.

#define NP_MAX(a,b) (((a)>(b))?(a):(b))

bool np_hex_to_data_length(const char* hex, size_t hexLength, uint8_t* data, size_t dataLength);
bool np_hex_to_data(const char* hex, uint8_t* data, size_t dataLength);

// outputLength is dataLength * 2
void np_data_to_hex(uint8_t* data, size_t dataLength, char* output);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
