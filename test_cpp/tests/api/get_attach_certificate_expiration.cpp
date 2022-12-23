#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"
#include "../../util/io_service.hpp"
#include "attached_test_device.hpp"
#include "../attach/basestation_fixture.hpp"

#include <thread>
#include <future>

#if defined(NABTO_DEVICE_GET_ATTACH_CERTIFICATE_EXPIRATION)

BOOST_FIXTURE_TEST_SUITE(get_attach_certificate_expiration, nabto::test::BasestationFixture, *boost::unit_test::timeout(10))

BOOST_AUTO_TEST_CASE(get_attach_certificate_expiration)
{

    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();
    uint64_t expiration = 42;

    NabtoDeviceError ec = nabto_device_get_attach_certificate_expiration(dev, &expiration);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    time_t n = time(NULL);

    BOOST_TEST(expiration > (uint64_t)n);
    uint64_t someTimeIn2035 = 2082701873;
    BOOST_TEST(expiration < someTimeIn2035);
}
BOOST_AUTO_TEST_SUITE_END()

#endif
