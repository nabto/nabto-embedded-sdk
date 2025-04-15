#include <nabto/nabto_device_test.h>

#include <platform/np_logging.h>

#include "cbor.h"

#include <nn/endian.h>

#define LOG NABTO_LOG_MODULE_TEST


bool test_cbor();
bool test_nn_endian();

NabtoDeviceError NABTO_DEVICE_API
nabto_device_test_misc(NabtoDevice* device) {
    if (!test_nn_endian()) {
        return NABTO_DEVICE_EC_UNKNOWN;
    }
    if (!test_cbor()) {
        return NABTO_DEVICE_EC_UNKNOWN;
    }
    return NABTO_DEVICE_EC_OK;
}


bool test_cbor_encode_int()
{
    uint8_t result[] = {
            0x18, 42, // 42
            0x19, 0x10, 0x92,  // 4242
            0x1a, 0x02,0x87,0x57,0xB2, // 42424242
            0x1b,0x00,0x0F,0x12,0x76,0x5D,0xF4,0xC9,0xB2 // 4242424242424242
    };

    uint8_t buffer[32];
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, sizeof(buffer), 0);

    if (cbor_encode_uint(&encoder, 42) != CborNoError ||
        cbor_encode_uint(&encoder, 4242) != CborNoError ||
        cbor_encode_uint(&encoder, 42424242) != CborNoError ||
        cbor_encode_uint(&encoder, 4242424242424242) != CborNoError)
    {
        return false;
    }

    size_t encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);
    if (encodedSize != sizeof(result)) {
        return false;
    }
    if (memcmp(result, buffer, encodedSize) != 0) {
        return false;
    }
    return true;
}

bool test_cbor_encode_text_string()
{
    // utf8 string of length 10
    uint8_t result[] = { 0x6a, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x6f, 0x72, 0x6c, 0x64 };

    CborEncoder encoder;
    uint8_t buffer[16];
    cbor_encoder_init(&encoder, buffer, sizeof(buffer), 0);
    if (cbor_encode_text_stringz(&encoder, "helloworld") != CborNoError) {
        return false;
    }
    size_t encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);
    if (encodedSize != sizeof(result)) {
        return false;
    }
    if (memcmp(result, buffer, encodedSize) != 0) {
        return false;
    }
    return true;

}

bool test_cbor() {
    if (!test_cbor_encode_text_string()) {
        NABTO_LOG_ERROR(LOG, "cbor test encode text string failed");
        return false;
    }

    if (!test_cbor_encode_int()) {
        NABTO_LOG_ERROR(LOG, "cbor int encode failed");
        return false;
    }

    return true;
}

bool test_nn_endian()
{
    uint64_t in = 4242424242424242;
    uint64_t out = nn_htonll(in);
    if (out != 12883096891320045312) {
        NABTO_LOG_ERROR(LOG, "nn_htonl failed");
        return false;
    }
    return true;
}
