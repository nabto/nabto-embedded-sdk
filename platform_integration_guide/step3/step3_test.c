#include <nabto/nabto_device_test.h>

#include <stdio.h>

static void log_callback(NabtoDeviceLogMessage* msg, void* data);

int main()
{
    // instead of calling nabto_device_new, we call
    // nabto_device_test_new to get a test instance with limited
    NabtoDevice* device = nabto_device_test_new();

    // Set the log level to trace to get all log messages.
    nabto_device_set_log_level(device, "trace");

    // Set a custom log print function
    nabto_device_set_log_callback(device, log_callback, NULL);

    // Call the test function which emits 4 different log lines.
    nabto_device_test_logging(device);

    // Set the level to info again.
    nabto_device_set_log_level(device, "info");

    printf("Logging test passed if ERROR, WARN, INFO and TRACE logs were seen in the console output\n");

    nabto_device_test_free(device);
}

void log_callback(NabtoDeviceLogMessage* msg, void* data)
{
    printf(" Log output: %5s %s\n", nabto_device_log_severity_as_string(msg->severity), msg->message);
}
