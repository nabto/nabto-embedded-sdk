#ifndef _NABTO_DEVICE_EVENT_QUEUE_H_
#define _NABTO_DEVICE_EVENT_QUEUE_H_

#include <platform/np_platform.h>

struct nabto_device_future;
struct nabto_device_mutex;

void libevent_event_queue_init(struct np_platform* pl, struct nabto_device_mutex* mutex);
void libevent_event_queue_deinit(struct np_platform* pl);

#endif
