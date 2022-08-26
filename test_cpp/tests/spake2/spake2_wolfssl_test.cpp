#if defined(NABTO_DEVICE_ENABLE_PASSWORD_AUTHENTICATION)
#if defined(NABTO_DEVICE_WOLFSSL)

#include <boost/test/unit_test.hpp>

#include "spake2_util.hpp"

#include <boost/test/data/test_case.hpp>
#include <test_platform.hpp>

#include <core/nc_spake2.h>
#include <platform/np_platform.h>
#include <modules/wolfssl/nm_wolfssl_spake2.h>

BOOST_AUTO_TEST_SUITE(spake2)

BOOST_AUTO_TEST_CASE(wolfssl_spake2, * boost::unit_test::timeout(120))
{
    BOOST_TEST(nm_wolfssl_spake2_test());
}

BOOST_AUTO_TEST_SUITE_END();

#endif
#endif
