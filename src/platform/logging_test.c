#include "nabto_logging_test.h"
#include "unit_test.h"
#include <platform/nabto_logging.h>
#include <modules/logging/nabto_unix_logging.h>


void nabto_logging_test()
{
    nabto_log.log=&unix_log;
    NABTO_LOG_FATAL(42, "FATAL: This is %s: %d", "a number", 24);
    NABTO_LOG_ERROR(42, "ERROR: This is %s: %d", "a number", 24);
    NABTO_LOG_WARN(42, "WARN: This is %s: %d", "a number", 24);
    NABTO_LOG_INFO(42, "INFO: This is %s: %d", "a number", 24);
    NABTO_LOG_DEBUG(42, "DEBUG: This is %s: %d", "a number", 24);
    NABTO_LOG_TRACE(42, "TRACE: This is %s: %d", "a number", 24);
    NABTO_TEST_CHECK(true);
}
