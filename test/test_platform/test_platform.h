#ifndef _TEST_PLATFORM_H_
#define _TEST_PLATFORM_H_

#include <platform/np_platform.h>

struct test_platform {
    struct np_platform pl;
};
void test_platform_init(struct test_platform* tp);

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

#endif
