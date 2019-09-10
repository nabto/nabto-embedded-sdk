#ifndef _TEST_PLATFORM_H_
#define _TEST_PLATFORM_H_

#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

struct test_platform {
    struct np_platform pl;
    bool stopped;
};

void test_platform_init(struct test_platform* tp);
void test_platform_init_epoll(struct test_platform* tp);
void test_platform_init_select_unix(struct test_platform* tp);
void test_platform_init_select_win(struct test_platform* tp);

/* /\** */
/*  * Wait for ever for incoming traffic from the network. */
/*  * @return The number of filedescriptors available for read */
/*  *\/ */
/* int test_platform_inf_wait(struct test_platform* tp); */

/* /\** */
/*  * Wait a maximum of 'ms' milliseconds for incoming traffic from */
/*  * the network. */
/*  * @return The number of filedescriptors available for read */
/*  *\/ */
/* int test_platform_timed_wait(struct test_platform* tp, uint32_t ms); */

/* /\** */
/*  * Read incoming traffic signalled by wait. */
/*  * @param nfds  The number of filedescriptors ready for read */
/*  *\/ */
/* void test_platform_read(struct test_platform* tp, int nfds); */

void test_platform_run(struct test_platform* tp);

void test_platform_stop(struct test_platform* tp);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
