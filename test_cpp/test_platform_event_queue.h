#ifndef _TEST_PLATFORM_EVENT_QUEUE_H_
#define _TEST_PLATFORM_EVENT_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

void test_platform_event_queue_init(struct np_platform* pl, struct event_base* eventBase);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
