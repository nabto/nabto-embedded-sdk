#include <boost/test/unit_test.hpp>

#include "../../util/helper.hpp"
#include "../attach/basestation_fixture.hpp"
#include "attached_test_device.hpp"

#include <util/live_allocations.hpp>

BOOST_FIXTURE_TEST_SUITE(attached_shutdown, nabto::test::BasestationFixture, *boost::unit_test::timeout(30))

BOOST_AUTO_TEST_CASE(free_attached_device)
{
    // The device is stopped while its DTLS connection to the basestation is
    // open. The attacher closes the connection, nabto_device_stop waits for
    // the close to finish, and nothing is left after the device is freed.
    nabto::test::LiveAllocations allocations;
    {
        nabto::test::AttachedTestDevice attachedTestDevice;
        attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());
    }
    BOOST_TEST(allocations.live() == 0u);
}

BOOST_AUTO_TEST_SUITE_END()
