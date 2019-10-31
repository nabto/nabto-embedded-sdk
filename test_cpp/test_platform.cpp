#include "test_platform.hpp"

#ifdef HAVE_EPOLL
#include "test_platform_epoll.hpp"
#else
#include "test_platform_select_unix.hpp"
#endif

namespace nabto {
namespace test {

std::unique_ptr<TestPlatform> TestPlatform::create()
{
#ifdef HAVE_EPOLL
    return std::unique_ptr<TestPlatform>(new nabto::test::TestPlatformEpoll());
#else
    return std::unique_ptr<TestPlatform>(new nabto::test::TestPlatformSelectUnix());
#endif
}

} }
