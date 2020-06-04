#ifndef _TEST_PLATFORM_EVENT_QUEUE_H_
#define _TEST_PLATFORM_EVENT_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

struct test_platform_event_queue* test_platform_event_queue_init(struct event_base* eventBase);
void test_platform_event_queue_deinit(struct test_platform_event_queue*);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
