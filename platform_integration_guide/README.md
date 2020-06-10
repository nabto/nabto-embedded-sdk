# Platform Integration Guide

The platform integration guide consists of several steps.


## Step 1

The task in step 1 is to create an implementation of the threads,
mutex and conditions which the rest of the code depends on.

## Step 2

The task in step 2 is to create a platform adapter such that
`nabto_device_test_new` and `nabto_device_test_free` can be
called. Further if the threads from step 1 is indeed implemented
properly we should also be able to see a working future test.

## Step 3

The task in step 3 is to get log output to the console from the
platform.

## Step 4

The task for step 4 is to implement timestamps for the device.

## Step 5

The task for step 5 is to implement an event queue for the device.
