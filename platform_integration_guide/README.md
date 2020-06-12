
# Platform Integration Guide

The platform integration guide consists of several steps. Each step
introduces a bit more functionality. After the last step you have
successfully created a platform integration for a nabto device
library.

The integration procedure includes template tools to test the functions made. Since new integrations will be made on unknown systems/platforms (and possible not have a main() function as entrypoint and possible not have a printf function), the integrator will need to port the test templates, including setting up the files for compilation. 

The templates have been made with simplicity in mind. As an example here is the step1_threads test:

```
#include <nabto/nabto_device_test.h>

#include <stdio.h>

int main()
{
    NabtoDeviceError ec = nabto_device_test_threads();
    if (ec == NABTO_DEVICE_EC_OK) {
        printf("Threads test passed\n");
    } else {
        printf("Threads test failed\n");
    }
}
```

So to use the template the integrator should copy the block inside the main function and create a main or similar on the target and put the block inside.  

The source files to be linked onto the target can be seen in the CMakeLists.txt :

```
set(src
  # we have cheated a bit and used an already existing implementation
  # of the threads interface.
  ../../src/modules/threads/unix/nabto_device_threads_unix.c

  # Test program for the threads interface
  ../../src/api_test/nabto_device_test_threads.c

  # Needed utility function to run the test.
  ../../src/api/nabto_device_error.c

  threads_test.c
  )
```

So both the `nabto_device_test_threads.c` and `nabto_device_error.c` should be reused (linked onto the integration target), but instead of using the threads module in `src/modules/threads/unix/nabto_device_threads_unix.c` the integrator should supply its own implementation (which is need to be tested).


The integration procedure with supporting tests are as follows:


1. step1_threads
   Testing of the threads interface functions.
2. step2_basic_device
   Test of the most basic "empty" device.  
3. step3_logging
   Test of logging on the target platform
4. step4_timestamps
   Test of the target platform timestamp module implementation (the simplest module)
5. step5_event_queue
   Test of the event queue
6. step6_dns
   Test of DNS integration
7. step7_network
   Test of the network (UDP/TCP) integration module
8. step8_local_ip
   Test of the local_ip module
9. step9_mdns
   Test of MDNS



## Step 1

The task in step 1 is to create an implementation of the threads
interface which is used in a few places. The threads interface defines
functionality to work with threads, mutexes and conditions.


## Step 2

The task in step 2 is to create a platform adapter such that
`nabto_device_test_new` and `nabto_device_test_free` can be
called. Further if the threads from step 1 is indeed implemented
properly we should also be able to see a working future test.

## Step 3

The task in this step 3 is to get log output to the console from the
platform.

## Step 4

The task in this step is to implement timestamps.

## Step 5

The task in this step is to implement an event queue.

## Step 6

The task here is to implement dns functionality.

## Step 7

The task is to implement UDP and TCP networking. The test requires an
udp and tcp echo server to be running somewhere else. We porovide such
a utility for testing purposes.

## Step 8

The task is to implement functionality such that the local ip of the
system can be retrieved.

## Step 9

The task is to implement mdns functionality. The mdns functionality
can be tested with a general mdns client.

### List of useful mdns clients

  * Mac: Use the dns-sd tool from a shell.
  * Windows: install the bonjour sdk and use the dns-sd tool from a shell.
  * Linux: install avahi-utils and use avahi-browse
  * Android: service browser https://play.google.com/store/apps/details?id=com.druk.servicebrowser&hl=en
