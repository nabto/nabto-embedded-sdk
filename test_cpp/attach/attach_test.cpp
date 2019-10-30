#include <boost/test/unit_test.hpp>

#include <util/io_service.hpp>
#include <util/test_logger.hpp>

#include "attach_server.hpp"

BOOST_AUTO_TEST_SUITE(attach)

BOOST_AUTO_TEST_CASE(attach)
{
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer(ioService->getIoService(), testLogger);


}

BOOST_AUTO_TEST_CASE(redirect)
{
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer(ioService->getIoService(), testLogger);
    // TODO
}

BOOST_AUTO_TEST_SUITE_END()
