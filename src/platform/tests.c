#include "tests.h"

void nabto_platform_test_run_all()
{
    nabto_event_queue_tests();
    nabto_platform_tests();
    nabto_ip_address_tests();
    nabto_logging_tests();
}
