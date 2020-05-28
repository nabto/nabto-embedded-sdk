#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

static std::string testKey = R"(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGSX4jqg22NscdsQ9Y8mNqbsC4uMu0/Dm2/fnLXKrmaHoAoGCCqGSM49
AwEHoUQDQgAEU9UWaRNJDxf8r5pPFCWjlJ1ypoqlfst+0vj90eH3XbzyRVGLzNmj
JyPCeZp8gYzccecB2jsFU30UP6lOMMK1Lw==
-----END EC PRIVATE KEY-----
)";

// openssl ec -in key.pem -outform der | openssl asn1parse -inform der
std::vector<uint8_t> testKeyRawPrivateKey = {
    0x64, 0x97, 0xE2, 0x3A, 0xA0, 0xDB, 0x63, 0x6C, 0x71, 0xDB, 0x10, 0xF5, 0x8F, 0x26, 0x36, 0xA6, 0xEC, 0x0B, 0x8B, 0x8C, 0xBB, 0x4F, 0xC3, 0x9B, 0x6F, 0xDF, 0x9C, 0xB5, 0xCA, 0xAE, 0x66, 0x87
};


BOOST_AUTO_TEST_SUITE(private_key)

BOOST_AUTO_TEST_CASE(check_fingerprint)
{
    std::string fp1;
    std::string fp2;
    // test that fingerprint from testKey is the same as the fingerprint from the testKeyRawPrivateKey
    {
        NabtoDevice* device = nabto_device_new();
        nabto_device_set_private_key(device, testKey.c_str());
        char* fp;
        nabto_device_get_device_fingerprint_full_hex(device, &fp);
        fp1 = std::string(fp);
        nabto_device_string_free(fp);
        nabto_device_free(device);
    }

    {
        NabtoDevice* device = nabto_device_new();
        BOOST_TEST(nabto_device_set_private_key_secp256r1(device, testKeyRawPrivateKey.data(), testKeyRawPrivateKey.size()) == NABTO_DEVICE_EC_OK);
        char* fp;
        nabto_device_get_device_fingerprint_full_hex(device, &fp);
        fp2 = std::string(fp);
        nabto_device_string_free(fp);
        nabto_device_free(device);
    }

    BOOST_TEST(fp1 == fp2);

}
BOOST_AUTO_TEST_SUITE_END()
