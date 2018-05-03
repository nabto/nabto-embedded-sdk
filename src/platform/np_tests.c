#include "np_tests.h"

void np_platform_test_run_all()
{
    np_event_queue_tests();
    np_platform_tests();
    np_ip_address_tests();
    np_logging_tests();
}
