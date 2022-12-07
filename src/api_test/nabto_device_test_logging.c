#include <nabto/nabto_device_test.h>

#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_TEST

void NABTO_DEVICE_API
nabto_device_test_logging(NabtoDevice* device)
{
    (void)device;
    int i = 42;
    const char* str = "test";
    double d = 42.2;
    NABTO_LOG_ERROR(LOG, "Test error level, int: %d, string: %s, double: %f", i, str, d);
    NABTO_LOG_WARN(LOG, "Test warn level, int: %d, string: %s, double: %f", i, str, d);
    NABTO_LOG_INFO(LOG, "Test info level, int: %d, string: %s, double: %f", i, str, d);
    NABTO_LOG_TRACE(LOG, "Test trace level, int: %d, string: %s, double: %f", i, str, d);
}
