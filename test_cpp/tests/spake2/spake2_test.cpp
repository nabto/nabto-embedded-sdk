#include <nabto/nabto_device_config.h>
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)

#include <boost/test/unit_test.hpp>

#include "spake2_util.hpp"

#include <boost/test/data/test_case.hpp>
#include <test_platform.hpp>

#include <core/nc_spake2.h>
#include <platform/np_platform.h>
#include <modules/mbedtls/nm_mbedtls_spake2.h>

BOOST_AUTO_TEST_SUITE(spake2)

BOOST_AUTO_TEST_CASE(check_platform_init, * boost::unit_test::timeout(120))
{
    auto tp = nabto::test::TestPlatform::create();
    np_platform* pl = tp->getPlatform();
    BOOST_TEST(pl->spake2.create != (void*)NULL);
    BOOST_TEST(pl->spake2.destroy != (void*)NULL);
    BOOST_TEST(pl->spake2.calculate_key != (void*)NULL);
    BOOST_TEST(pl->spake2.key_confirmation != (void*)NULL);
}

BOOST_AUTO_TEST_CASE(calculate_key, * boost::unit_test::timeout(120))
{
    auto tp = nabto::test::TestPlatform::create();
    np_platform* pl = tp->getPlatform();

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
    BOOST_TEST(cli.calculateT(T) == 0);

    memcpy(req->clientFingerprint, clientFp, 32);
    memcpy(req->deviceFingerprint, deviceFp, 32);
    req->T = (uint8_t*)calloc(1, T.size());
    memcpy(req->T, T.data(), T.size());
    req->Tlen = T.size();

    uint8_t S[256];
    size_t SLen = sizeof(S);
    uint8_t key[32];

    BOOST_TEST(pl->spake2.calculate_key(NULL, req, password.c_str(), S, &SLen, key)== NABTO_EC_OK);

    BOOST_TEST(SLen == (size_t)65);
    BOOST_TEST(cli.calculateK(S, SLen) == 0);
    BOOST_TEST(cli.calculateKey());

    // If both agree on key, S must be correct
    BOOST_TEST(memcmp(key, cli.key_.data(), cli.key_.size()) == 0);

    nc_spake2_password_request_free(req);
}

BOOST_AUTO_TEST_CASE(key_confirmation, * boost::unit_test::timeout(120))
{
    auto tp = nabto::test::TestPlatform::create();
    np_platform* pl = tp->getPlatform();
    uint8_t key[] = {0x22, 0xd1, 0x43, 0x34, 0xb2, 0xda, 0x17, 0xca,
                         0xa5, 0x1f, 0xef, 0xdf, 0xcf, 0xe5, 0x7b, 0xe3,
                         0xc2, 0xc5, 0x66, 0x7c, 0xa8, 0x3d, 0x3d, 0x1e,
                         0xd9, 0xfe, 0x7e, 0x6d, 0xe5, 0x9c, 0xaf, 0xae};
    uint8_t payload[] = {0x77,   0xf1, 0x8e, 0x15, 0xbe, 0x32, 0x3e, 0x2c,
                         0xbb, 0xf1, 0x72, 0x7e, 0xcf, 0xbe, 0x41, 0x00,
                         0xce, 0xfb, 0x9d, 0x99, 0x6f, 0xef, 0x31, 0x83,
                         0x97, 0xc5, 0x7d, 0x1e, 0x5c, 0x76, 0xf2, 0xdb};
    uint8_t expected[] = {0x22,   0x56, 0xfc, 0x0f, 0x37, 0x09, 0xcf, 0x37,
                       0xe7, 0x26, 0xd5, 0x10, 0x47, 0x32, 0x2b, 0x55,
                       0x6c, 0x63, 0x3c, 0xb8, 0x24, 0xad, 0x5c, 0xc0,
                       0xbf, 0x19, 0x00, 0x4a, 0x91, 0x16, 0xb8, 0x3b};

    uint8_t hash1[32];

    BOOST_TEST(pl->spake2.key_confirmation(NULL, payload, 32, key, 32, hash1, 32) == NABTO_EC_OK);
    BOOST_TEST(memcmp(expected, hash1, 32) == 0);
}

BOOST_AUTO_TEST_SUITE_END()

#endif
