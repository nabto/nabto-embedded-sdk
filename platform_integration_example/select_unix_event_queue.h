#ifndef _SELECT_UNIX_EVENT_QUEUE_H_
#define _SELECT_UNIX_EVENT_QUEUE_H_

#include <modules/event_queue/nm_event_queue.h>
#include <src/api/nabto_device_threads.h>

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
struct nm_event_queue;
struct np_platform;

struct select_unix_event_queue {
    struct nabto_device_thread* queueThread;
    struct nabto_device_mutex* mutex;
    struct nabto_device_mutex* queueMutex;
    struct nabto_device_condition* condition;
    struct nm_event_queue eventQueue;
    struct np_timestamp ts;
    bool stopped;
};

void select_unix_event_queue_init(struct select_unix_event_queue* queue, struct nabto_device_mutex* mutex, struct np_timestamp* ts);

struct np_event_queue select_unix_event_queue_get_impl(struct select_unix_event_queue* queue);

void select_unix_event_queue_deinit(struct select_unix_event_queue* queue);

void select_unix_event_queue_stop_blocking(struct select_unix_event_queue* queue);



#endif
