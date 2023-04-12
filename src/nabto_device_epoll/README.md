This is an linux epoll optimized platform for the Nabto Embedded SDK.

It runs the platform in two threads.

Thread 1: This thread runs all the io and events in a loop based on EPOLL.

Thread 2: This thread is for future resolving in the nabto_device.h api.
