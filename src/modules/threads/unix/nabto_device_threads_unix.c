#include <api/nabto_device_threads.h>

#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>

#define LOG NABTO_LOG_MODULE_API

struct nabto_device_thread {
    pthread_t thread;
};

struct nabto_device_mutex {
    pthread_mutex_t mut;
};

struct nabto_device_condition {
    pthread_cond_t cond;
};


struct nabto_device_thread* nabto_device_threads_create_thread()
{
    struct nabto_device_thread* thread = calloc(1, sizeof(struct nabto_device_thread));
    if (thread == NULL) {
        return NULL;
    }
    return thread;
}

struct nabto_device_mutex* nabto_device_threads_create_mutex()
{
    struct nabto_device_mutex* mut = (struct nabto_device_mutex*)malloc(sizeof(struct nabto_device_mutex));
    if (mut == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&mut->mut, NULL) != 0) {
        free(mut);
        return NULL;
    }
    return mut;
}

struct nabto_device_condition* nabto_device_threads_create_condition()
{
    struct nabto_device_condition* cond = (struct nabto_device_condition*)malloc(sizeof(struct nabto_device_condition));
    if (cond == NULL) {
        return NULL;
    }
    if (pthread_cond_init(&cond->cond, NULL) != 0) {
        free(cond);
        return NULL;
    }
    return cond;
}

void nabto_device_threads_free_thread(struct nabto_device_thread* thread)
{
    free(thread);
}

void nabto_device_threads_free_mutex(struct nabto_device_mutex* mutex)
{
    pthread_mutex_destroy(&mutex->mut);
    free(mutex);
}

void nabto_device_threads_free_cond(struct nabto_device_condition* cond)
{
    pthread_cond_destroy(&cond->cond);
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
    if (pthread_create(&thread->thread, NULL, run_routine, data) != 0) {
        return NABTO_EC_UNKNOWN;
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
    gettimeofday(&tp, NULL);
    long future_us = tp.tv_usec+ms*1000;
    ts.tv_nsec = (future_us % 1000000) * 1000;
    ts.tv_sec = tp.tv_sec + future_us / 1000000;
    pthread_cond_timedwait(&cond->cond, &mut->mut, &ts);
}
