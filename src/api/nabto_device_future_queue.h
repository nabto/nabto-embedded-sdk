#ifndef NABTO_DEVICE_FUTURE_QUEUE_H
#define NABTO_DEVICE_FUTURE_QUEUE_H

#include <nabto/nabto_device.h>
//#include <api/nabto_device_defines.h>
#include <nn/llist.h>
#include <platform/np_error_code.h>

/**
 * This defines a queue of futures which is ready to be resolved by an
 * asynchronouos callback.
 */


#ifdef __cplusplus
extern "C" {
#endif

struct nabto_device_context;

struct nabto_device_future_queue {
    struct nn_llist futureList;
    // list mutex since the list will be manipulated from two
    // different threads.
    struct nabto_device_mutex* mutex;

    // the thread that executes the callbacks for resolved futures.
    struct nabto_device_thread* thread;


    struct nabto_device_condition* condition;
    bool stopped;
};

struct nabto_device_future;

np_error_code nabto_device_future_queue_init(struct nabto_device_future_queue* queue);
void nabto_device_future_queue_deinit(struct nabto_device_future_queue* queue);

void nabto_device_future_queue_stop(struct nabto_device_future_queue* queue);

void nabto_device_future_queue_post(struct nabto_device_future_queue* queue, struct nabto_device_future* future);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NABTO_DEVICE_FUTURE_QUEUE_H
