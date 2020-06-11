#include <nabto/nabto_device_test.h>

#include <stdio.h>

static void log_callback(NabtoDeviceLogMessage* msg, void* data);

int main()
{
    NabtoDevice* device = nabto_device_test_new();

    nabto_device_set_log_callback(device, log_callback, NULL);
    nabto_device_set_log_level(device, "info");

    // Run the Local IP test. The test passes if the local ips for the
    // system is printet in the console output.
    nabto_device_test_local_ip(device);
    printf("Test is passed if the local ips is written to the console output\n");

    nabto_device_test_free(device);
}

void log_callback(NabtoDeviceLogMessage* msg, void* data)
{
    printf(" Log output: %5s %s\n", nabto_device_log_severity_as_string(msg->severity), msg->message);
}
