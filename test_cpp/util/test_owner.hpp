#pragma once

#include <platform/np_ref.h>

namespace nabto {
namespace test {

/**
 * Owner of completion events created by a test. Every completion event has
 * an owner, see np_completion_event_init. The test object outlives its
 * events, so the release does nothing.
 */
class TestOwner {
 public:
    TestOwner()
    {
        np_ref_init(&ref, NULL, &release);
    }

    struct np_ref ref;

 private:
    static void release(struct np_ref* r)
    {
        (void)r;
    }
};

} } // namespace
