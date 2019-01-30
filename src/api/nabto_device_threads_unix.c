#include "nabto_device_threads.h"

#include <platform/np_logging.h>

#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>

#define LOG NABTO_LOG_MODULE_API

struct nabto_device_thread {
    pthread_t thread;
    pthread_attr_t attr;
};

struct nabto_device_mutex {
    pthread_mutex_t mut;
};

struct nabto_device_condition {
    pthread_cond_t cond;
};


struct nabto_device_thread* nabto_device_threads_create_thread()
{
    struct nabto_device_thread* thread = (struct nabto_device_thread*)malloc(sizeof(struct nabto_device_thread));
    if (thread == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate thread");
        return NULL;
    }
    if (pthread_attr_init(&thread->attr) !=0) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize pthread_attr");
        free(thread);
        return NULL;
    }
    if (pthread_attr_setdetachstate(&thread->attr, PTHREAD_CREATE_DETACHED) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to set detach state for pthread_attr");
        pthread_attr_destroy(&thread->attr);
        free(thread);
        return NULL;
    }    
    return thread;
}

struct nabto_device_mutex* nabto_device_threads_create_mutex()
{
    struct nabto_device_mutex* mut = (struct nabto_device_mutex*)malloc(sizeof(struct nabto_device_mutex));
    if (mut == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate mutex");
        return NULL;
    }
    if (pthread_mutex_init(&mut->mut, NULL) != 0) { 
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
        free(mut);
        return NULL; 
    }
    return mut;    
}

struct nabto_device_condition* nabto_device_threads_create_condition()
{
    struct nabto_device_condition* cond = (struct nabto_device_condition*)malloc(sizeof(struct nabto_device_condition));
    if (cond == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate condition");
        return NULL;
    }
    if (pthread_cond_init(&cond->cond, NULL) != 0) {
        NABTO_LOG_ERROR(LOG, "condition init has failed");
        free(cond);
        return NULL;
    }
    return cond;    
}

void nabto_device_threads_free_thread(struct nabto_device_thread* thread)
{
    pthread_attr_destroy(&thread->attr);
    free(thread);
}

void nabto_device_threads_free_mutex(struct nabto_device_mutex* mutex)
{
    free(mutex);
}

void nabto_device_threads_free_cond(struct nabto_device_condition* cond)
{
    free(cond);
}

void nabto_device_threads_join(struct nabto_device_thread* thread)
{
    pthread_join(thread->thread, NULL);
}

void nabto_device_threads_mutex_lock(struct nabto_device_mutex* mutex)
{
    pthread_mutex_lock(&mutex->mut);
}

void nabto_device_threads_mutex_unlock(struct nabto_device_mutex* mutex)
{
    pthread_mutex_unlock(&mutex->mut);
}

np_error_code nabto_device_threads_run(struct nabto_device_thread* thread, void *(*run_routine) (void *), void* data)
{
    if (pthread_create(&thread->thread, &thread->attr, run_routine, data) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to create pthread");
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

void nabto_device_threads_cond_signal(struct nabto_device_condition* cond)
{
    pthread_cond_signal(&cond->cond);
}

void nabto_device_threads_cond_wait(struct nabto_device_condition* cond,
                                    struct nabto_device_mutex* mut)
{
    pthread_cond_wait(&cond->cond, &mut->mut);
}

void nabto_device_threads_cond_timed_wait(struct nabto_device_condition* cond,
                                          struct nabto_device_mutex* mut,
                                          uint32_t ms)
{
    struct timespec ts;
    struct timeval tp;
    int rc = gettimeofday(&tp, NULL);
    long future_us = tp.tv_usec+ms*1000;
    ts.tv_nsec = (future_us % 1000000) * 1000;
    ts.tv_sec = tp.tv_sec + future_us / 1000000;
    pthread_cond_timedwait(&cond->cond, &mut->mut, &ts);
}


