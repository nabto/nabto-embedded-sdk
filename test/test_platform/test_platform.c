/**
 * Wait for ever for incoming traffic from the network.
 * @return The number of filedescriptors available for read
 */
int test_platform_inf_wait(struct test_platform* tp)
{

}

/**
 * Wait a maximum of 'ms' milliseconds for incoming traffic from
 * the network.
 * @return The number of filedescriptors available for read
 */
int test_platform_timed_wait(struct test_platform* tp, uint32_t ms)
{

}

/**
 * Read incoming traffic signalled by wait.
 * @param nfds  The number of filedescriptors ready for read
 */
void test_platform_read(struct test_platform* tp, int nfds)
{

}
