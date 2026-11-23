#include <nabto/nabto_device_config.h>
#if defined(NABTO_DEVICE_OPENSSL)

#include <boost/test/unit_test.hpp>

#include <modules/openssl/nm_openssl_util.h>
#include <platform/np_allocator.h>

#include "../attach/certificates.hpp"

#include <mbedtls/build_info.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include <string.h>

namespace {

int dummyRandom(void* context, unsigned char* output, size_t outputLen)
{
    (void)context;
    for (size_t i = 0; i < outputLen; i++) {
        output[i] = 42;
    }
    return 0;
}

// The fingerprint as the mbedtls module calculates it.
void mbedtls_fingerprint(const std::string& privateKey, uint8_t* fp)
{
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    BOOST_REQUIRE(mbedtls_pk_parse_key(&key, (const unsigned char*)privateKey.c_str(), privateKey.size() + 1, NULL, 0, dummyRandom, NULL) == 0);
    uint8_t buffer[256];
    int len = mbedtls_pk_write_pubkey_der(&key, buffer, sizeof(buffer));
    BOOST_REQUIRE(len > 0);
    mbedtls_sha256(buffer + sizeof(buffer) - len, (size_t)len, fp, 0);
    mbedtls_pk_free(&key);
}

} // namespace

BOOST_AUTO_TEST_SUITE(dtls_openssl)

BOOST_AUTO_TEST_CASE(fingerprint_matches_mbedtls)
{
    uint8_t opensslFp[32];
    uint8_t mbedtlsFp[32];
    BOOST_TEST(nm_openssl_get_fingerprint_from_private_key(nabto::test::privateKey.c_str(), opensslFp) == NABTO_EC_OK);
    mbedtls_fingerprint(nabto::test::privateKey, mbedtlsFp);
    BOOST_TEST(memcmp(opensslFp, mbedtlsFp, 32) == 0);
}

BOOST_AUTO_TEST_CASE(created_private_key_is_sec1_and_readable_by_mbedtls)
{
    char* key = NULL;
    BOOST_REQUIRE(nm_openssl_util_create_private_key(&key) == NABTO_EC_OK);
    std::string pem(key);
    np_free(key);

    // The format the mbedtls and wolfssl modules write.
    BOOST_TEST(pem.rfind("-----BEGIN EC PRIVATE KEY-----", 0) == 0u);

    uint8_t opensslFp[32];
    uint8_t mbedtlsFp[32];
    BOOST_TEST(nm_openssl_get_fingerprint_from_private_key(pem.c_str(), opensslFp) == NABTO_EC_OK);
    mbedtls_fingerprint(pem, mbedtlsFp);
    BOOST_TEST(memcmp(opensslFp, mbedtlsFp, 32) == 0);
}

BOOST_AUTO_TEST_CASE(created_certificate_matches_mbedtls_certificate)
{
    char* crt = NULL;
    BOOST_REQUIRE(nm_openssl_create_crt_from_private_key(nabto::test::privateKey.c_str(), &crt) == NABTO_EC_OK);
    std::string pem(crt);
    np_free(crt);

    mbedtls_x509_crt c;
    mbedtls_x509_crt_init(&c);
    BOOST_REQUIRE(mbedtls_x509_crt_parse(&c, (const unsigned char*)pem.c_str(), pem.size() + 1) == 0);

    char name[64];
    BOOST_TEST(mbedtls_x509_dn_gets(name, sizeof(name), &c.subject) > 0);
    BOOST_TEST(std::string(name) == "CN=nabto");
    BOOST_TEST(mbedtls_x509_dn_gets(name, sizeof(name), &c.issuer) > 0);
    BOOST_TEST(std::string(name) == "CN=nabto");
    BOOST_TEST(c.version == 3);
    BOOST_TEST(c.valid_from.year == 2001);
    BOOST_TEST(c.valid_from.mon == 1);
    BOOST_TEST(c.valid_from.day == 1);
    BOOST_TEST(c.valid_to.year == 2049);
    BOOST_TEST(c.valid_to.mon == 12);
    BOOST_TEST(c.valid_to.day == 31);
    BOOST_TEST(c.serial.len == 1u);
    BOOST_TEST(c.serial.p[0] == 1u);
    BOOST_TEST(mbedtls_x509_crt_has_ext_type(&c, MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) != 0);
    // The certificate is self signed.
    uint32_t flags = 0;
    BOOST_TEST(mbedtls_x509_crt_verify(&c, &c, NULL, NULL, &flags, NULL, NULL) == 0);

    // The certificate has the public key of the private key.
    X509* x509 = nm_openssl_util_load_certificate((const unsigned char*)pem.c_str(), pem.size());
    BOOST_REQUIRE(x509 != NULL);
    uint8_t crtFp[32];
    uint8_t keyFp[32];
    BOOST_TEST(nm_openssl_util_fp_from_crt(x509, crtFp) == NABTO_EC_OK);
    BOOST_TEST(nm_openssl_get_fingerprint_from_private_key(nabto::test::privateKey.c_str(), keyFp) == NABTO_EC_OK);
    BOOST_TEST(memcmp(crtFp, keyFp, 32) == 0);

    uint64_t expiration = 0;
    BOOST_TEST(nm_openssl_util_get_expiration(x509, &expiration) == NABTO_EC_OK);
    // 2049-12-31T23:59:59Z
    BOOST_TEST(expiration == 2524607999u);

    X509_free(x509);
    mbedtls_x509_crt_free(&c);
}

BOOST_AUTO_TEST_CASE(record_sequence_number)
{
    // content type, version, epoch 0x0102, sequence number 0x030405060708
    const uint8_t header[] = {0x17, 0xfe, 0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x10};
    uint64_t seq = 0;
    BOOST_TEST(nm_openssl_util_record_sequence_number(header, sizeof(header), &seq));
    BOOST_TEST(seq == 0x0102030405060708ull);
    BOOST_TEST(!nm_openssl_util_record_sequence_number(header, 10, &seq));
}

BOOST_AUTO_TEST_CASE(mtu_larger_than_max_record_size)
{
    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    BOOST_REQUIRE(ctx != NULL);
    SSL* ssl = SSL_new(ctx);
    BOOST_REQUIRE(ssl != NULL);

    // A communication buffer larger than the largest record must not make the
    // connection fail.
    BOOST_TEST(nm_openssl_util_configure_ssl(ssl, UINT16_MAX) == NABTO_EC_OK);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

BOOST_AUTO_TEST_SUITE_END()

#endif
