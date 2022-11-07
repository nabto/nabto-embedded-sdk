#ifndef _SELECT_UNIX_EVENT_QUEUE_H_
#define _SELECT_UNIX_EVENT_QUEUE_H_

#include <modules/event_queue/nm_event_queue.h>
#include <api/nabto_device_threads.h>

/**
 * Since we are running everything from one thread we can directly use
 * the nm_event_queue module without any custom locking on event
 * posting. When executing events we need to have the appropriate
 * locks such that the core of the device is synchronized with the
 * application which uses the nabto_device.h api.
 *
 * We do however need to notify the select platform when events or
 * timed events is posted to the event queue such that they can be
 * handled if they are posted from the outside.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct nm_event_queue;
struct np_platform;

struct thread_event_queue {
    struct nabto_device_thread* queueThread;
    // coreMutex is used to synchronize all access to the core of the
    // platform. The coreMutex needs to be taken before event
    // callbacks is executed.
    struct nabto_device_mutex* coreMutex;

    // The queueMutex protects the queue, The queue post function can
    // be called without the coreMutex being taken.
    struct nabto_device_mutex* queueMutex;
    struct nabto_device_condition* condition;
    struct nm_event_queue eventQueue;
    struct np_timestamp ts;
    bool stopped;
};

np_error_code thread_event_queue_init(struct thread_event_queue* queue, struct nabto_device_mutex* coreMutex, struct np_timestamp* ts);

void thread_event_queue_deinit(struct thread_event_queue* queue);

// start the thread
np_error_code thread_event_queue_run(struct thread_event_queue* queue);

struct np_event_queue thread_event_queue_get_impl(struct thread_event_queue* queue);

bool thread_event_queue_do_one(struct thread_event_queue* queue);

void thread_event_queue_stop_blocking(struct thread_event_queue* queue);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
