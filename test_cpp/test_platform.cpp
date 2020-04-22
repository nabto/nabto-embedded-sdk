#include "test_platform.hpp"

#ifdef HAVE_EPOLL
#include "test_platform_epoll.hpp"
#endif

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

std::vector<std::shared_ptr<TestPlatform> > TestPlatform::multi()
{
    std::vector<std::shared_ptr<TestPlatform> > platforms;
#if defined(HAVE_LIBEVENT)
    platforms.push_back(std::make_shared<TestPlatformLibevent>());
#endif
#if defined(HAVE_SELECT_UNIX)
    platforms.push_back(std::make_shared<TestPlatformSelectUnix>());
#endif
    return platforms;
}

} }
