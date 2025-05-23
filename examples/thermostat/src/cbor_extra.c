#include "cbor_extra.h"

#include <math.h>
#include <math.h>
#include <stdint.h>

static inline float decode_halff(uint16_t half)
{
    int exp = (half >> 10) & 0x1f;
    int mant = half & 0x3ff;
    float mantf = NAN, expf = NAN, val = NAN;
    if (exp == 0) {
        // mant is max 10 bit
        mantf = (float)mant;
        expf = 1.0f / (1 << 24);
        val = mantf * expf;
    } else if (exp != 31) {
        // mant is max 10 bit
        mantf = (float)mant + 1024.0f;
        expf = exp >= 25 ? (float)(1 << (exp - 25)) : 1.0f / (float)(1 << (25 - exp));
        val = mantf * expf;
    } else {
        val = mant == 0 ? INFINITY : NAN;
    }
    return half & 0x8000 ? -val : val;
}

bool cbor_value_is_floating_point(CborValue* value)
{
    return cbor_value_is_half_float(value) || cbor_value_is_float(value) || cbor_value_is_double(value);
}

CborError cbor_value_get_floating_point(CborValue* value, double* fp)
{
    if (cbor_value_is_half_float(value)) {
        uint16_t halff = 0;
        CborError ec = cbor_value_get_half_float(value, &halff);
        if (ec != CborNoError) {
            return ec;
        }
        float f = decode_halff(halff);
        *fp = f;
        return ec;
    }
    if (cbor_value_is_float(value)) {
        float f = NAN;
        CborError ec = cbor_value_get_float(value, &f);
        if (ec != CborNoError) {
            return ec;
        }
        *fp = f;
        return ec;
    }
    if (cbor_value_is_double(value)) {
        return cbor_value_get_double(value, fp);
    }
    return CborErrorIllegalType;
}
