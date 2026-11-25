#include <boost/test/unit_test.hpp>

#include <api/nabto_device_threads.h>
#include <modules/event_queue/thread_event_queue.h>
#include <platform/np_completion_event.h>
#include <platform/np_ref.h>

namespace {

uint32_t test_now_ms(struct np_timestamp* obj)
{
    (void)obj;
    return 0;
}

const struct np_timestamp_functions testTimestampFunctions = {
    &test_now_ms
};

/**
 * An event queue without a queue thread. Events are run with runAll from
 * the test thread.
 */
class TestQueue {
 public:
    TestQueue()
    {
        coreMutex_ = nabto_device_threads_create_mutex();
        ts_.mptr = &testTimestampFunctions;
        ts_.data = NULL;
        BOOST_REQUIRE(thread_event_queue_init(&queue_, coreMutex_, &ts_) == NABTO_EC_OK);
        eq_ = thread_event_queue_get_impl(&queue_);
    }
    ~TestQueue()
    {
        thread_event_queue_deinit(&queue_);
        nabto_device_threads_free_mutex(coreMutex_);
    }
    void runAll()
    {
        while (thread_event_queue_do_one(&queue_)) {
        }
    }
    struct np_event_queue* eq() { return &eq_; }

 private:
    struct nabto_device_mutex* coreMutex_;
    struct np_timestamp ts_;
    struct thread_event_queue queue_;
    struct np_event_queue eq_;
};

struct Owner {
    struct np_ref ref;
    struct np_completion_event ev;
    int callbacks = 0;
    np_error_code lastEc = NABTO_EC_OK;
    bool released = false;
    bool armedInCallback = false;
};

void owner_release(struct np_ref* ref)
{
    Owner* owner = (Owner*)((char*)ref - offsetof(Owner, ref));
    owner->released = true;
}

void owner_callback(const np_error_code ec, void* userData)
{
    Owner* owner = (Owner*)userData;
    owner->callbacks++;
    owner->lastEc = ec;
    owner->armedInCallback = np_completion_event_is_armed(&owner->ev);
    // The owner must stay alive until the callback has returned.
    BOOST_TEST(!owner->released);
}

void tracker_idle(void* userData)
{
    int* calls = (int*)userData;
    (*calls)++;
}

} // namespace

BOOST_AUTO_TEST_SUITE(np_completion_event_suite)

BOOST_AUTO_TEST_CASE(arm_resolve_callback)
{
    TestQueue q;
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();

    np_completion_event_arm(&owner.ev);
    BOOST_TEST(np_completion_event_is_armed(&owner.ev));
    np_completion_event_resolve(&owner.ev, NABTO_EC_ABORTED);
    // The callback is called from the event queue, never from resolve.
    BOOST_TEST(owner.callbacks == 0);
    q.runAll();
    BOOST_TEST(owner.callbacks == 1);
    BOOST_TEST(owner.lastEc == NABTO_EC_ABORTED);
    BOOST_TEST(!owner.armedInCallback);
    BOOST_TEST(!np_completion_event_is_armed(&owner.ev));

    // The event can be used for the next operation.
    np_completion_event_arm(&owner.ev);
    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    q.runAll();
    BOOST_TEST(owner.callbacks == 2);

    np_completion_event_deinit(&owner.ev);
    BOOST_TEST(np_lifetime_violation_count() == violations);
}

BOOST_AUTO_TEST_CASE(disarm)
{
    TestQueue q;
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();

    np_completion_event_arm(&owner.ev);
    BOOST_TEST(owner.ref.count == (size_t)2);
    np_completion_event_disarm(&owner.ev);
    BOOST_TEST(owner.ref.count == (size_t)1);
    BOOST_TEST(!np_completion_event_is_armed(&owner.ev));

    np_completion_event_deinit(&owner.ev);
    np_ref_put(&owner.ref);
    BOOST_TEST(owner.released);
    BOOST_TEST(np_lifetime_violation_count() == violations);
}

BOOST_AUTO_TEST_CASE(owner_is_released_after_the_last_callback)
{
    TestQueue q;
    int idle = 0;
    struct np_ref_tracker tracker = { 0, 0, &tracker_idle, &idle };
    Owner owner;
    np_ref_init(&owner.ref, &tracker, &owner_release);
    BOOST_TEST(tracker.live == (size_t)1);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);

    np_completion_event_arm(&owner.ev);
    BOOST_TEST(tracker.outstanding == (size_t)1);
    np_completion_event_resolve(&owner.ev, NABTO_EC_ABORTED);

    // The owner drops its reference while the resolve is queued. The
    // object is not released before the callback has run.
    np_ref_put(&owner.ref);
    BOOST_TEST(!owner.released);
    BOOST_TEST(tracker.live == (size_t)1);
    BOOST_TEST(tracker.outstanding == (size_t)1);
    BOOST_TEST(idle == 0);

    q.runAll();
    BOOST_TEST(owner.callbacks == 1);
    BOOST_TEST(owner.released);
    BOOST_TEST(tracker.live == (size_t)0);
    BOOST_TEST(tracker.outstanding == (size_t)0);
    BOOST_TEST(idle == 1);
    np_completion_event_deinit(&owner.ev);
}

BOOST_AUTO_TEST_CASE(owner_without_outstanding_operations_is_released_at_once)
{
    struct np_ref_tracker tracker = { 0, 0, NULL, NULL };
    Owner owner;
    np_ref_init(&owner.ref, &tracker, &owner_release);
    np_ref_get(&owner.ref);
    np_ref_put(&owner.ref);
    BOOST_TEST(!owner.released);
    np_ref_put(&owner.ref);
    BOOST_TEST(owner.released);
    BOOST_TEST(tracker.live == (size_t)0);
}

#if !defined(NABTO_DEVICE_LIFETIME_CHECKS)
// With lifetime checks enabled a violation aborts the program, so the
// violations are only tested without them.

BOOST_AUTO_TEST_CASE(resolve_twice_is_a_violation)
{
    TestQueue q;
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();

    np_completion_event_arm(&owner.ev);
    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    q.runAll();
    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    q.runAll();
    BOOST_TEST(np_lifetime_violation_count() == violations + 1);
    np_completion_event_deinit(&owner.ev);
}

BOOST_AUTO_TEST_CASE(resolve_without_arm_is_a_violation)
{
    TestQueue q;
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();
    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    q.runAll();
    BOOST_TEST(owner.callbacks == 1);
    BOOST_TEST(np_lifetime_violation_count() == violations + 1);
    np_completion_event_deinit(&owner.ev);
}

BOOST_AUTO_TEST_CASE(arm_twice_is_a_violation)
{
    TestQueue q;
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();

    np_completion_event_arm(&owner.ev);
    np_completion_event_arm(&owner.ev);
    BOOST_TEST(np_lifetime_violation_count() == violations + 1);
    // The second arm does not take another reference.
    BOOST_TEST(owner.ref.count == (size_t)2);

    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    q.runAll();
    np_completion_event_deinit(&owner.ev);
    np_ref_put(&owner.ref);
    BOOST_TEST(owner.released);
}

BOOST_AUTO_TEST_CASE(deinit_while_armed_is_a_violation)
{
    TestQueue q;
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();

    np_completion_event_arm(&owner.ev);
    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    np_completion_event_deinit(&owner.ev);
    BOOST_TEST(np_lifetime_violation_count() == violations + 1);

    // The queued resolve is cancelled and the callback is never called.
    q.runAll();
    BOOST_TEST(owner.callbacks == 0);
    // The reference held by the armed event is leaked rather than dropped,
    // since dropping it could free the memory the event is in.
    np_ref_put(&owner.ref);
    BOOST_TEST(!owner.released);
}

BOOST_AUTO_TEST_CASE(reinit_while_armed_is_a_violation)
{
    TestQueue q;
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, &owner.ref) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();
    np_completion_event_arm(&owner.ev);
    np_completion_event_reinit(&owner.ev, &owner_callback, &owner);
    BOOST_TEST(np_lifetime_violation_count() == violations + 1);
    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    q.runAll();
    np_completion_event_deinit(&owner.ev);
}

BOOST_AUTO_TEST_CASE(arm_without_owner_is_a_violation)
{
    TestQueue q;
    Owner owner;
    BOOST_REQUIRE(np_completion_event_init(q.eq(), &owner.ev, &owner_callback, &owner, NULL) == NABTO_EC_OK);
    size_t violations = np_lifetime_violation_count();
    np_completion_event_arm(&owner.ev);
    BOOST_TEST(np_lifetime_violation_count() == violations + 1);
    np_completion_event_resolve(&owner.ev, NABTO_EC_OK);
    q.runAll();
    BOOST_TEST(owner.callbacks == 1);
    np_completion_event_deinit(&owner.ev);
}

BOOST_AUTO_TEST_CASE(put_on_released_object_is_a_violation)
{
    Owner owner;
    np_ref_init(&owner.ref, NULL, &owner_release);
    np_ref_put(&owner.ref);
    size_t violations = np_lifetime_violation_count();
    np_ref_put(&owner.ref);
    np_ref_get(&owner.ref);
    BOOST_TEST(np_lifetime_violation_count() == violations + 2);
}

#endif

BOOST_AUTO_TEST_SUITE_END()
