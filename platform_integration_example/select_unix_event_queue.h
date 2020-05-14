#ifndef _SELECT_UNIX_EVENT_QUEUE_H_
#define _SELECT_UNIX_EVENT_QUEUE_H_

/**
 * Since we are running everything from one thread we can directly use
 * the nm_event_queue module without any custom locking on event
 * posting. When executing events we need to have the appropriate
 * locks such that the core of the device is synchronized with the
 * application which uses the nabto_device.h api.
 */
struct select_unix_platform;
struct np_platform;
void select_unix_event_queue_init(struct select_unix_platform* platform, struct np_platform* pl);



#endif
