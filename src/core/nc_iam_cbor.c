#include "nc_iam_cbor.h"

#include <cbor.h>


bool nc_iam_cbor_users_get(struct nc_device_context* device, const char* name, void** cbor, size_t* cborLength)
{
    uint8_t tmpBuffer[1024];

    CborEncoder encoder;
    cbor_encoder_init(&encoder, tmpBuffer, 1024, 0);

    CborEncoder map;

    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "roles");
    {
        CborEncoder roles;
        cbor_encoder_create_array(&map, &roles, CborIndefiniteLength);

        cbor_encode_text_stringz(&roles, "foo");
        cbor_encode_text_stringz(&roles, "bar");
        cbor_encoder_close_container(&map, &roles);
    }
    {
        CborEncoder fingerprints;
        cbor_encoder_create_array(&map, &fingerprints, CborIndefiniteLength);
        cbor_encoder_close_container(&map, &fingerprints);
    }

    cbor_encoder_close_container(&encoder, &map);

    *cborLength = cbor_encoder_get_buffer_size(&encoder, tmpBuffer);

    *cbor = malloc(*cborLength);
    memcpy(*cbor, tmpBuffer, *cborLength);
    return true;
}
