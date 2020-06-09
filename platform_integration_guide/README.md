# Platform Integration Guide

The platform integration guide consists of several steps.


## Step 1

The task in step 1 is to create an implementation of the threads,
mutex and conditions which the rest of the code depends on.

## Step 2

The task in step 2 is to create a platform adapter such that
`nabto_device_test_new` and `nabto_device_test_free` can be called.

## Step 3

The task in step 3 is to get log output to the console from the
platform.
