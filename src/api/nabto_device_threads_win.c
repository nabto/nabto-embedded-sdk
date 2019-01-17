#include "nabto_device_threads.h"

#include <platform/np_logging.h>

struct nabto_device_thread {

};

struct nabto_device_mutex {

};

struct nabto_device_condition {

};

struct nabto_device_thread* nabto_device_threads_create_thread()
{

}

struct nabto_device_mutex* nabto_device_threads_create_mutex()
{

}

struct nabto_device_condition* nabto_device_threads_create_cond()
{

}

void nabto_device_threads_free_thread(struct nabto_device_thread* thread)
{

}

void nabto_device_threads_free_mutex(struct nabto_device_mutex* mutext)
{

}

void nabto_device_threads_free_cond(struct nabto_device_condition* cond)
{

}

void nabto_device_threads_join(struct nabto_device_thread* thread)
{

}

void nabto_device_threads_mutex_lock(struct nabto_device_mutex* mutex)
{

}

void nabto_device_threads_mutex_unlock(struct nabto_device_mutex* mutex)
{

}

np_error_code nabto_device_threads_run(struct nabto_device_thread* thread,
                                       void *(*run_routine) (void *), void* data)
{

}

void nabto_device_threads_cond_signal(struct nabto_device_condition* cond)
{

}

void nabto_device_threads_cond_wait(struct nabto_device_condition* cond,
                                    struct nabto_device_mutex* mut)
{

}

void nabto_device_threads_cond_timed_wait(struct nabto_device_condition* cond,
                                          struct nabto_device_mutex* mut,
                                          uint32_t ms)
{

}

