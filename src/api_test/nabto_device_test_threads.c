/**
 * Test of threads implementation.
 */

#include <nabto/nabto_device_test.h>
#include <api/nabto_device_threads.h>

#include <platform/np_allocator.h>

struct threads_test {
    struct nabto_device_mutex* mutex;
    struct nabto_device_condition* condition;
    struct nabto_device_thread* thread;
};

static void* thread_body(void* data);

NabtoDeviceError NABTO_DEVICE_API nabto_device_test_threads()
{
    // create a new thread which signals on a condition such that join
    // is called on the thread and everything closes down in a
    // controlled manner

    struct threads_test* t = np_calloc(1, sizeof(struct threads_test));

    t->mutex = nabto_device_threads_create_mutex();
    t->condition = nabto_device_threads_create_condition();
    t->thread = nabto_device_threads_create_thread();

    if (t->mutex == NULL || t->condition == NULL || t->thread == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    // take the mutex such that the condition is not notified from the
    // new thread before we have had a change to wait for the signal.
    nabto_device_threads_mutex_lock(t->mutex);

    nabto_device_threads_run(t->thread, &thread_body, t);

    nabto_device_threads_cond_wait(t->condition, t->mutex);
    nabto_device_threads_mutex_unlock(t->mutex);

    nabto_device_threads_join(t->thread);

    nabto_device_threads_free_cond(t->condition);
    nabto_device_threads_free_mutex(t->mutex);
    nabto_device_threads_free_thread(t->thread);

    np_free(t);
    return NABTO_DEVICE_EC_OK;
}


void* thread_body(void* data)
{
    struct threads_test* t = data;
    nabto_device_threads_cond_signal(t->condition);
    return NULL;
}
