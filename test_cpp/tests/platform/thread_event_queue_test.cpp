#include <boost/test/unit_test.hpp>

#include <api/nabto_device_threads.h>
#include <modules/event_queue/thread_event_queue.h>
#include <platform/np_event_queue_wrapper.h>

#include <nn/llist.h>

#include <atomic>
#include <chrono>
#include <thread>

namespace {

uint32_t test_now_ms(struct np_timestamp* obj)
{
    (void)obj;
    return 0;
}

const struct np_timestamp_functions testTimestampFunctions = {
    &test_now_ms
};

void count_callback(void* data)
{
    std::atomic<int>* calls = static_cast<std::atomic<int>*>(data);
    (*calls)++;
}

/**
 * Wait up to timeout for the queue thread to take the posted event off the
 * queue.
 */
bool wait_for_dequeue(struct thread_event_queue* queue, std::chrono::milliseconds timeout)
{
    auto end = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < end) {
        nabto_device_threads_mutex_lock(queue->queueMutex);
        bool empty = nn_llist_empty(&queue->eventQueue.events);
        nabto_device_threads_mutex_unlock(queue->queueMutex);
        if (empty) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_SUITE(thread_event_queue_suite)

BOOST_AUTO_TEST_CASE(destroy_event_while_queue_thread_waits_for_core_lock, *boost::unit_test::timeout(60))
{
    struct nabto_device_mutex* coreMutex = nabto_device_threads_create_mutex();
    struct np_timestamp ts;
    ts.mptr = &testTimestampFunctions;
    ts.data = NULL;

    struct thread_event_queue queue;
    BOOST_REQUIRE(thread_event_queue_init(&queue, coreMutex, &ts) == NABTO_EC_OK);
    struct np_event_queue eq = thread_event_queue_get_impl(&queue);
    BOOST_REQUIRE(thread_event_queue_run(&queue) == NABTO_EC_OK);

    std::atomic<int> calls(0);
    for (int i = 0; i < 5; i++) {
        // A core thread holding the core lock posts an event and then
        // destroys it. The callback must not run, even if the queue thread
        // was woken up by the post in between.
        nabto_device_threads_mutex_lock(coreMutex);
        struct np_event* event = NULL;
        BOOST_REQUIRE(np_event_queue_create_event(&eq, &count_callback, &calls, &event) == NABTO_EC_OK);
        np_event_queue_post(&eq, event);
        // Before the fix, the queue thread takes the event off the queue and
        // then blocks on the core lock. After the fix, it takes the core lock
        // before taking the event, so this times out.
        wait_for_dequeue(&queue, std::chrono::milliseconds(100));
        np_event_queue_destroy_event(&eq, event);
        nabto_device_threads_mutex_unlock(coreMutex);
    }

    // Let the queue thread run any event it may have taken.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    BOOST_TEST(calls == 0);

    thread_event_queue_stop_blocking(&queue);
    thread_event_queue_deinit(&queue);
    nabto_device_threads_free_mutex(coreMutex);
}

BOOST_AUTO_TEST_CASE(events_are_executed, *boost::unit_test::timeout(60))
{
    struct nabto_device_mutex* coreMutex = nabto_device_threads_create_mutex();
    struct np_timestamp ts;
    ts.mptr = &testTimestampFunctions;
    ts.data = NULL;

    struct thread_event_queue queue;
    BOOST_REQUIRE(thread_event_queue_init(&queue, coreMutex, &ts) == NABTO_EC_OK);
    struct np_event_queue eq = thread_event_queue_get_impl(&queue);
    BOOST_REQUIRE(thread_event_queue_run(&queue) == NABTO_EC_OK);

    std::atomic<int> calls(0);
    struct np_event* event = NULL;
    BOOST_REQUIRE(np_event_queue_create_event(&eq, &count_callback, &calls, &event) == NABTO_EC_OK);
    struct np_event* timedEvent = NULL;
    BOOST_REQUIRE(np_event_queue_create_event(&eq, &count_callback, &calls, &timedEvent) == NABTO_EC_OK);

    np_event_queue_post(&eq, event);
    np_event_queue_post_timed_event(&eq, timedEvent, 0);

    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (calls < 2 && std::chrono::steady_clock::now() < end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    BOOST_TEST(calls == 2);

    nabto_device_threads_mutex_lock(coreMutex);
    np_event_queue_destroy_event(&eq, event);
    np_event_queue_destroy_event(&eq, timedEvent);
    nabto_device_threads_mutex_unlock(coreMutex);

    thread_event_queue_stop_blocking(&queue);
    thread_event_queue_deinit(&queue);
    nabto_device_threads_free_mutex(coreMutex);
}

BOOST_AUTO_TEST_SUITE_END()
