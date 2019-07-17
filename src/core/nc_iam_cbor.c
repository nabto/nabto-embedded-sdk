#include "nc_iam_cbor.h"

#include <cbor.h>

static bool nc_iam_cbor_validate_policy(struct nc_device_context* context, void* cbor, size_t cborLength);


bool nc_iam_cbor_policy_create(struct nc_device_context* device, const char* name, void* cbor, size_t cborLength)
{
    struct nc_iam* iam;
    if (!nc_iam_cbor_validate_policy(device, cbor, cborLength)) {
        return false;
    }

    struct nc_iam_policy* p = nc_iam_find_policy(iam, name);
    if (!p) {
        p = nc_iam_policy_new(iam, name);
    }
    nc_iam_policy_set_cbor(p, cbor, cborLength);

    return true;
}



/**
 * Format of a policy
{
  "Version": 1,
  "Name": "uniquename",
  "Statement": {
    "Effect": "Allow|Deny",
    "Action": [ "module:action1", "module:action2" ],
    "Condition": {
      "And": [{"Or": [..., ...]}, {"StringEqual": ["${connection:UserId}", "bar"]}]
    }
  }
}
 */

bool nc_iam_cbor_validate_policy(struct nc_device_context* context, void* cbor, size_t cborLength)
{
    return true;
}

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
