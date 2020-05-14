#ifndef _THREAD_EVENT_QUEUE_H_
#define _THREAD_EVENT_QUEUE_H_

/**
 * Event queue implementation based on the thread abstraction found in nabto_device_threads.h
 */

void thread_event_queue_init(struct np_platform* pl, struct nabto_device_mutex* mutex);
void thread_event_queue_deinit(struct np_platform* pl);

#endif
