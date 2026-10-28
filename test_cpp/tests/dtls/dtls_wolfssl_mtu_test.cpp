#include <nabto/nabto_device_config.h>
#if defined(NABTO_DEVICE_WOLFSSL)

#include <boost/test/unit_test.hpp>

#include <modules/wolfssl/nm_wolfssl_util.h>

BOOST_AUTO_TEST_SUITE(dtls_wolfssl_mtu)

BOOST_AUTO_TEST_CASE(mtu_larger_than_max_record_size)
{
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    BOOST_REQUIRE(ctx != NULL);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    BOOST_REQUIRE(ssl != NULL);

    // A communication buffer larger than the largest record wolfSSL makes
    // must not make the connection fail.
    BOOST_TEST(nm_wolfssl_util_set_mtu(ssl, UINT16_MAX) == NABTO_EC_OK);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

BOOST_AUTO_TEST_SUITE_END()

#endif
