#ifndef _NC_CBOR_H_
#define _NC_CBOR_H_

#include <string.h>
#include <stdbool.h>

#include <tinycbor/cbor.h>

/**
 * copy a text string from the cbor value to the out variable, the memory needed
 * is allocated in the function and limited by the maxLength variable.
 *
 * @return true iff the text string is copied to out and it is shorter than maxLength.
 */
bool nc_cbor_copy_text_string(CborValue* s, char** out, size_t maxLength);

/**
 * copy a byte string into a buffer
 */
bool nc_cbor_copy_byte_string(CborValue* s, uint8_t** out, size_t* outLength, size_t maxLength);

/**
 * return true if the error is not OK or OOM. This is useful when encoding with a null buffer to calculate allocation size.
 */
bool nc_cbor_err_not_oom(CborError e);

/**
 * Returns from the function if the embedded cbor function `e` returns with an error
 * and the error is not CborErrorOutOfMemory.
 */
#define NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(e)              \
    do {                                                   \
        CborError ec = e;                                  \
        if ((ec & ~CborErrorOutOfMemory) != CborNoError) { \
            return ec;                                     \
        }                                                  \
    } while(0)

#endif
