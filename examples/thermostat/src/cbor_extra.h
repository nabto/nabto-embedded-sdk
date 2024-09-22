#ifndef _CBOR_EXTRA_H_
#define _CBOR_EXTRA_H_

#include <tinycbor/cbor.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return true if value is either half float, float or double.
 */
bool cbor_value_is_floating_point(CborValue* value);

CborError cbor_value_get_floating_point(CborValue* value, double* fp);

#ifdef __cplusplus
} // extern c
#endif

#endif
