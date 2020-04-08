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


namespace nabto {
namespace test {

std::unique_ptr<TestPlatform> TestPlatform::create()
{
#if defined(HAVE_EPOLL)
    return std::unique_ptr<TestPlatform>(new nabto::test::TestPlatformEpoll());
#elif defined(HAVE_SELECT_UNIX)
    return std::unique_ptr<TestPlatform>(new nabto::test::TestPlatformSelectUnix());
#elif defined(HAVE_LIBEVENT)
    return std::unique_ptr<TestPlatform>(new nabto::test::TestPlatformLibevent());
#else
    #error no test platform exists
    return std::nullptr;
#endif
}

} }
