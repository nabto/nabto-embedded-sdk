#include "nc_cbor.h"

#include <platform/np_allocator.h>

bool nc_cbor_copy_text_string(CborValue* s, char** out, size_t maxLength) {
    *out = NULL;
    if (!cbor_value_is_text_string(s)) {
        return false;
    }
    size_t length = 0;
    if (cbor_value_calculate_string_length(s, &length) != CborNoError) {
        return false;
    }
    if (length > maxLength) {
        return false;
    }
    length += 1; // room for null byte
    *out = np_calloc(1, length+1);
    if (*out == NULL) {
        return false;
    }
    if (cbor_value_copy_text_string(s, *out, &length, NULL) != CborNoError) {
        np_free(*out);
        *out = NULL;
        return false;
    }
    return true;
}

bool nc_cbor_copy_byte_string(CborValue* s, uint8_t** out, size_t* outLength, size_t maxLength) {
    *out = NULL;
    *outLength = 0;
    if (!cbor_value_is_byte_string(s)) {
        return false;
    }
    size_t length = 0;
    if (cbor_value_calculate_string_length(s, &length) != CborNoError) {
        return false;
    }
    if (length > maxLength) {
        return false;
    }
    *out = np_calloc(1, length);
    if (*out == NULL) {
        return false;
    }
    if (cbor_value_copy_byte_string(s, *out, &length, NULL) != CborNoError) {
        np_free(*out);
        *out = NULL;
        return false;
    }
    *outLength = length;
    return true;
}
