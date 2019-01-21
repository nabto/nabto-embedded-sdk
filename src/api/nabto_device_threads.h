#ifndef NABTO_DEVICE_THREADS_H
#define NABTO_DEVICE_THREADS_H

#include <platform/np_error_code.h>
#include <nabto_types.h>

struct nabto_device_thread;

struct nabto_device_mutext;

struct nabto_device_condition;

struct nabto_device_thread* nabto_device_threads_create_thread(void);
struct nabto_device_mutex* nabto_device_threads_create_mutex(void);
struct nabto_device_condition* nabto_device_threads_create_cond(void);

void nabto_device_threads_free_thread(struct nabto_device_thread* thread);
void nabto_device_threads_free_mutex(struct nabto_device_mutex* mutext);
void nabto_device_threads_free_cond(struct nabto_device_condition* cond);

void nabto_device_threads_join(struct nabto_device_thread* thread);

void nabto_device_threads_mutex_lock(struct nabto_device_mutex* mutex);
void nabto_device_threads_mutex_unlock(struct nabto_device_mutex* mutex);

np_error_code nabto_device_threads_run(struct nabto_device_thread* thread,
                                       void *(*run_routine) (void *), void* data);

void nabto_device_threads_cond_signal(struct nabto_device_condition* cond);
void nabto_device_threads_cond_wait(struct nabto_device_condition* cond,
                                    struct nabto_device_mutex* mut);
void nabto_device_threads_cond_timed_wait(struct nabto_device_condition* cond,
                                          struct nabto_device_mutex* mut,
                                          uint32_t ms);

#endif //NABTO_DEVICE_THREADS_H
