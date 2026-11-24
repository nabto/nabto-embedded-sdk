#include <nabto/nabto_device_config.h>
#if defined(NABTO_DEVICE_OPENSSL)
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)

#include <boost/test/unit_test.hpp>

#include "spake2_util.hpp"

#include <core/nc_spake2.h>
#include <platform/np_platform.h>
#include <modules/openssl/nm_openssl_spake2.h>

static int dummyRandom(void* context, unsigned char* output, size_t outputLen)
{
    (void)context;
    for (size_t i = 0; i < outputLen; i++) {
        output[i] = 42;
    }
    return 0;
}

BOOST_AUTO_TEST_SUITE(openssl_spake2)

BOOST_AUTO_TEST_CASE(calculate_openssl_key_deterministically, * boost::unit_test::timeout(120))
{
    auto req = nc_spake2_password_request_new();
    uint8_t clientFp[] = {0xcf, 0xf2, 0xf6, 0x5c, 0xd1, 0x03, 0x48, 0x8b,
                          0x8c, 0xb2, 0xb9, 0x3e, 0x83, 0x8a, 0xcc, 0x0f,
                          0x71, 0x9d, 0x6d, 0xea, 0xe3, 0x7f, 0x8a, 0x4b,
                          0x74, 0xfa, 0x82, 0x52, 0x44, 0xd2, 0x8a, 0xf8};
    uint8_t deviceFp[] = {0x73, 0xe5, 0x30, 0x42, 0x55, 0x1c, 0x12, 0x8a,
                          0x49, 0x2c, 0xfd, 0x91, 0x0b, 0x9b, 0xa6, 0x7f,
                          0xff, 0xd2, 0xca, 0xb6, 0xc0, 0x23, 0xb5, 0x0c,
                          0x10, 0x99, 0x22, 0x89, 0xf4, 0xc2, 0x3d, 0x54};

    const std::string password = "FFzeqrpJTVF4";
    nabto::test::Spake2Client cli(password, clientFp, deviceFp);

    std::vector<uint8_t> T;
    BOOST_TEST(cli.calculateTWithCustomRandom(T, dummyRandom, NULL) == 0);

    memcpy(req->clientFingerprint, clientFp, 32);
    memcpy(req->deviceFingerprint, deviceFp, 32);
    req->T = (uint8_t*)calloc(1, T.size());
    memcpy(req->T, T.data(), T.size());
    req->Tlen = T.size();

    uint8_t S[256];
    size_t SLen = sizeof(S);
    uint8_t key[32];

    // mbedtls generates y = 0x2a2a...2a from dummyRandom.
    uint8_t y[32];
    memset(y, 42, sizeof(y));

    BOOST_TEST(nm_openssl_spake2_calculate_key_with_y(req, y, sizeof(y), password.c_str(), S, &SLen, key) == NABTO_EC_OK);
    BOOST_TEST(SLen == (size_t)65);

    // The same reference output as the mbedtls module calculates with
    // dummyRandom, see spake2_mbedtls_test.cpp
    uint8_t expectedKey[] = {0x5c, 0x5d, 0x50, 0x41, 0xd4, 0x63, 0x4b, 0x16,
                             0xcf, 0x7b, 0x79, 0xa7, 0x01, 0xac, 0xd9, 0x25,
                             0xbe, 0x9a, 0x3e, 0x36, 0x04, 0x36, 0xa5, 0xbb,
                             0xcb, 0x08, 0xd3, 0x8e, 0xe1, 0xf7, 0x64, 0x10};

    BOOST_TEST(memcmp(key, expectedKey, 32) == 0);

    // The client agrees on the key.
    BOOST_TEST(cli.calculateK(S, SLen) == 0);
    BOOST_TEST(cli.calculateKey());
    BOOST_TEST(memcmp(key, cli.key_.data(), cli.key_.size()) == 0);

    nc_spake2_password_request_free(req);
}

BOOST_AUTO_TEST_CASE(invalid_point_is_rejected, * boost::unit_test::timeout(120))
{
    auto req = nc_spake2_password_request_new();
    // A point which is not on the curve.
    std::vector<uint8_t> T(65, 0x01);
    T[0] = 0x04;
    req->T = (uint8_t*)calloc(1, T.size());
    memcpy(req->T, T.data(), T.size());
    req->Tlen = T.size();

    uint8_t S[256];
    size_t SLen = sizeof(S);
    uint8_t key[32];
    BOOST_TEST(nm_openssl_spake2_calculate_key_with_y(req, NULL, 0, "password", S, &SLen, key) != NABTO_EC_OK);
    nc_spake2_password_request_free(req);
}

BOOST_AUTO_TEST_SUITE_END()

#endif
#endif
