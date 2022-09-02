#include <boost/test/unit_test.hpp>

#include "basestation_fixture.hpp"
#include "../api/attached_test_device.hpp"


BOOST_AUTO_TEST_SUITE(basestation_fixture)

BOOST_AUTO_TEST_CASE(start_stop_ok1)
{
    {
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
    {
        nabto::test::BasestationFixture bf;
    }
    {
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
}

BOOST_AUTO_TEST_CASE(start_stop_ok2)
{
    {
        nabto::test::BasestationFixture bf;
    }
    {
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
}

BOOST_AUTO_TEST_CASE(start_stop_ok3)
{
    {
        nabto::test::BasestationFixture bf;
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
}

BOOST_AUTO_TEST_CASE(start_stop_ok4)
{
    {
        nabto::test::BasestationFixture bf;
    }
    {
        nabto::test::BasestationFixture bf;
    }
}
BOOST_AUTO_TEST_CASE(start_stop_ok5)
{
    {
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
    {
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
}

BOOST_AUTO_TEST_CASE(start_stop_ok6)
{
    {
        nabto::test::BasestationFixture bf;
    }
    {
        nabto::test::BasestationFixture bf;
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
}


BOOST_AUTO_TEST_CASE(start_stop_ok7)
{
    {
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
    {
        nabto::test::BasestationFixture bf;
        nabto::test::AttachedTestDevice attachedTestDevice;
    }
}


BOOST_AUTO_TEST_SUITE_END()
