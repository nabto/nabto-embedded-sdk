#include "cbor.h"

#include "compilersupport_p.h"

// copied from cborencoder.c
static inline bool would_overflow(CborEncoder *encoder, size_t len)
{
    ptrdiff_t remaining = (ptrdiff_t)encoder->end;
    remaining -= remaining ? (ptrdiff_t)encoder->data.ptr : encoder->data.bytes_needed;
    remaining -= (ptrdiff_t)len;
    return unlikely(remaining < 0);
}

// copied from cborencoder.c
static inline void advance_ptr(CborEncoder *encoder, size_t n)
{
    if (encoder->end)
        encoder->data.ptr += n;
    else
        encoder->data.bytes_needed += n;
}

// copied from cborencoder.c
static inline CborError append_to_buffer(CborEncoder *encoder, const void *data, size_t len)
{
    if (would_overflow(encoder, len)) {
        if (encoder->end != NULL) {
            len -= encoder->end - encoder->data.ptr;
            encoder->end = NULL;
            encoder->data.bytes_needed = 0;
        }

        advance_ptr(encoder, len);
        return CborErrorOutOfMemory;
    }

    memcpy(encoder->data.ptr, data, len);
    encoder->data.ptr += len;
    return CborNoError;
}

CborError cbor_encode_encoded_item(CborEncoder *encoder, const void *data, size_t len)
{
    return append_to_buffer(encoder, data, len);
}
