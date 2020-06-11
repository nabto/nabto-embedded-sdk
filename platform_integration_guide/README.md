# Platform Integration Guide

The platform integration guide consists of several steps. Each step
introduces a bit more functionality. After the last step you have
successfully created a platform integration for a nabto device
library.


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
