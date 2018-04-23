#include "nabto_logging_test.h"
#include "unit_test.h"
#include <platform/nabto_logging.h>
#include <modules/logging/nabto_unix_logging.h>


void nabto_logging_test()
{
    nabto_log.log=&unix_log;
    NABTO_LOG_INFO(42, "This is %s: %d", "a number", 24);
    NABTO_TEST_CHECK(true);
}
