#ifndef _NC_CBOR_H_
#define _NC_CBOR_H_

#include <string.h>
#include <stdbool.h>

#include <cbor.h>

/**
 * copy a text string from the cbor value to the out variable, the memory needed
 * is allocated in the function and limited by the maxLength variable.
 *
 * @return true iff the text string is copied to out and it is shorter than maxLength.
 */
bool nc_cbor_copy_text_string(CborValue* s, char** out, size_t maxLength);
#endif