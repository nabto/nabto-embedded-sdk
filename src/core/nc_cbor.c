#include "nc_cbor.h"

#include <stdlib.h>

bool nc_cbor_copy_text_string(CborValue* s, char** out, size_t maxLength) {
    if (!cbor_value_is_text_string(s)) {
        return false;
    }
    size_t length;
    if (cbor_value_calculate_string_length(s, &length) != CborNoError) {
        return false;
    }
    if (length > maxLength) {
        return false;
    }
    length += 1; // room for null byte
    *out = malloc(length+1);
    cbor_value_copy_text_string(s, *out, &length, NULL);
    return true;
}