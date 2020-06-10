#ifndef _TEST_PLATFORM_EVENT_QUEUE_H_
#define _TEST_PLATFORM_EVENT_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

struct test_platform_event_queue* test_platform_event_queue_init(struct event_base* eventBase);
void test_platform_event_queue_deinit(struct test_platform_event_queue*);

struct np_event_queue test_platform_event_queue_get_impl(struct test_platform_event_queue* eq);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
