#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>

#include <api/nabto_device_error.h>

BOOST_AUTO_TEST_SUITE(device_api)

BOOST_AUTO_TEST_CASE(error_codes_exists)
{
// This test fails with a compilation error if an error code is defined in nabto_device_error.h but not as an extern int in nabto_device.h
#define XX_ERROR(name) BOOST_TEST((NABTO_DEVICE_EC_##name) + 1 > 0);
    NABTO_DEVICE_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR
}

BOOST_AUTO_TEST_SUITE_END()
