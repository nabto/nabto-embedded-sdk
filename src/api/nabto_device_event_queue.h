#ifndef _NABTO_DEVICE_EVENT_QUEUE_H_
#define _NABTO_DEVICE_EVENT_QUEUE_H_

#include <platform/np_platform.h>
#include "nabto_device_threads.h"

struct nabto_device_future;

void nabto_device_event_queue_init(struct np_platform* pl, struct nabto_device_mutex* mutex);
void nabto_device_event_queue_deinit(struct np_platform* pl);

void nabto_device_event_queue_future_post(struct np_platform* pl, struct nabto_device_future* fut);

#endif
