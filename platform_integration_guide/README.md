
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



## Step 1 - threads

The task in step 1 is to create an implementation of the threads
interface which is used in a few places. The threads interface defines
functionality to work with threads, mutexes and conditions.
Please look above to see a description of how to integrate onto your own target.

## Step 2 - basic device

The task in step 2 is to create a platform adapter such that
`nabto_device_test_new` and `nabto_device_test_free` can be
called. Further if the threads from step 1 is indeed implemented
properly we should also be able to see a working future test.

The goal of the test is mostly to test that the new integration setup has correctly included and linked all the files files.
You will see a link error if all files needed from the Nabto Edge is not included.

If the test passes, you will know that the basic Nabto Platform (without any integration other than threads) is up and running.

The important file to examine is:

```include(${CMAKE_CURRENT_SOURCE_DIR}/../../nabto_primary_files.cmake)```

This file links to all the basic files need for the Nabto Edge Platform. If your platform does not use cmake you will need to somehow copy the links to your IDE.

Also the next steps will follow the structure of step2 of having a `basic_device_test.c` which is the test-runner (and the name will change for each step). Also the directory contains a `platform_integration.c` which is the platform bootstrap/setup (described [here](../doc/platform_integration_howto.md#apinabto_device_platformh). This file will contain more and more setup details regarding initialization of the system. You should be able to use `platform_integration.c` of higher steps (if the appropriate integration modules have been created and tested) for lower steps (ie. the `platform_integration.c` of step 8 should be able to be used in step 2).


## Step 3 - Logging

The task in this step 3 is to get log output to the console from the
platform. This will be very usefull if something fails in the later step since you can setup Nabto Edge to log internally.

## Step 4 - timestamps

This is the first real integration module to be implemented.
The task in this step is to implement timestamps.
More detailed information about the [Timestamp Integration here](../doc/platform_integration_howto.md#example-of-a-simple-module---struct-np_timestamp_functions)



## Step 5

The task in this step is to implement an event queue.
If your integration step 1 has been completed correctly you should be able to just use the standard supplied event queue which is dependent only on the threads implementation.


## Step 6

The task here is to implement dns functionality.
The DNS test will resolve the hostname : `ip.test.dev.nabto.com` using the standard DNS service.
Ie. the DNS client inside the integration target should be able to resolve this address.

The IPv4 A record should resolve to : 1.2.3.4

The IPv6 AAAA record should resolve to : 2001:db8::1

Please test that the target resolves the given hostname correctly.

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
