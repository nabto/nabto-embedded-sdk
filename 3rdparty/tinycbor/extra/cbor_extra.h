#ifndef _CBOR_EXTRA_H_
#define _CBOR_EXTRA_H_

#include <cbor.h>

#ifdef __cplusplus
extern "C" {
#endif

CborError cbor_encode_encoded_item(CborEncoder *encoder, const void *data, size_t len);

/**
 * Return true if value is either half float, float or double.
 */
bool cbor_value_is_floating_point(CborValue* value);

CborError cbor_value_get_floating_point(CborValue* value, double* fp);

#ifdef __cplusplus
} // extern c
#endif

#endif
