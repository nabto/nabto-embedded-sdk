#ifndef NABTO_DEVICE_EVENT_QUEUE_H_
#define NABTO_DEVICE_EVENT_QUEUE_H_

#include <platform/np_platform.h>

struct nabto_device_future;
struct nabto_device_mutex;
struct event_base;

struct np_event_queue libevent_event_queue_create(struct event_base* eventBase, struct nabto_device_mutex* mutex);

void libevent_event_queue_destroy(struct np_event_queue* pl);

#endif
