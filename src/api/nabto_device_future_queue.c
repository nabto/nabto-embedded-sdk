#include "nabto_device_future_queue.h"

#include <api/nabto_device_future.h>

#include <platform/np_logging.h>

static void* execution_thread(void* userData);

np_error_code nabto_device_future_queue_init(struct nabto_device_future_queue* queue)
{
    queue->thread = nabto_device_threads_create_thread();
    queue->mutex = nabto_device_threads_create_mutex();
    queue->condition = nabto_device_threads_create_condition();

    queue->initialized = true;

    if (queue->thread == NULL || queue->mutex == NULL || queue->condition == NULL) {
        nabto_device_future_queue_deinit(queue);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    nn_llist_init(&queue->futureList);

    np_error_code ec = nabto_device_threads_run(queue->thread, execution_thread, queue);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_queue_deinit(queue);
        return ec;
    }
    return NABTO_EC_OK;
}

void nabto_device_future_queue_deinit(struct nabto_device_future_queue* queue)
{
    if (!queue->initialized) {
        return;
    }
    //nabto_device_future_queue_stop(queue);
    nabto_device_threads_free_cond(queue->condition);
    nabto_device_threads_free_mutex(queue->mutex);
    nabto_device_threads_free_thread(queue->thread);
    queue->initialized = false;
}

void nabto_device_future_queue_stop(struct nabto_device_future_queue* queue)
{
    if (!queue->initialized) {
        return;
    }
    nabto_device_threads_mutex_lock(queue->mutex);
    if (queue->stopped) {
        return;
    }
    queue->stopped = true;
    nabto_device_threads_mutex_unlock(queue->mutex);
    nabto_device_threads_cond_signal(queue->condition);
    nabto_device_threads_join(queue->thread);
}

void nabto_device_future_queue_post(struct nabto_device_future_queue* queue, struct nabto_device_future* fut)
{
    nabto_device_threads_mutex_lock(queue->mutex);
    nn_llist_append(&queue->futureList, &fut->futureListNode, fut);
    nabto_device_threads_mutex_unlock(queue->mutex);
    nabto_device_threads_cond_signal(queue->condition);
}

void* execution_thread(void* userData)
{
    struct nabto_device_future_queue* queue = userData;
    while(true) {
        nabto_device_threads_mutex_lock(queue->mutex);
        if (!nn_llist_empty(&queue->futureList)) {
            struct nn_llist_iterator it = nn_llist_begin(&queue->futureList);
            struct nabto_device_future* future = nn_llist_get_item(&it);
            nn_llist_erase(&it);
            nabto_device_threads_mutex_unlock(queue->mutex);
            nabto_device_future_popped(future);
        } else if (queue->stopped) {
            nabto_device_threads_mutex_unlock(queue->mutex);
            return NULL;
        } else {
            nabto_device_threads_cond_wait(queue->condition, queue->mutex);
            nabto_device_threads_mutex_unlock(queue->mutex);
        }
    }
    return NULL;
}
