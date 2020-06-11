#include "test_platform.hpp"

#ifdef HAVE_SELECT_UNIX
#include "test_platform_select_unix.hpp"
#endif

#ifdef HAVE_LIBEVENT
#include "test_platform_libevent.hpp"
#endif

#include <vector>


namespace nabto {
namespace test {



std::unique_ptr<TestPlatform> TestPlatform::create()
{
#if defined(HAVE_LIBEVENT)
    return std::unique_ptr<TestPlatform>(new nabto::test::TestPlatformLibevent());
#elif defined(HAVE_SELECT_UNIX)
    return std::unique_ptr<TestPlatform>(new nabto::test::TestPlatformSelectUnix());
#else
    #error no test platform exists
    return std::nullptr;
#endif
}

std::vector<std::shared_ptr<TestPlatformFactory> > TestPlatformFactory::multi()
{
    std::vector<std::shared_ptr<TestPlatformFactory> > factories;
#if defined(HAVE_LIBEVENT)
    factories.push_back(std::make_shared<TestPlatformLibeventFactory>());
#endif
#if defined(HAVE_SELECT_UNIX)
    factories.push_back(std::make_shared<TestPlatformSelectUnixFactory>());
#endif
    return factories;

}


} }
