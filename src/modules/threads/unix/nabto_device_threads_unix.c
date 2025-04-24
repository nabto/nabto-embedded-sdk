#include <api/nabto_device_threads.h>

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <errno.h>
#include <pthread.h>

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


struct nabto_device_thread* nabto_device_threads_create_thread(void)
{
    struct nabto_device_thread* thread = np_calloc(1, sizeof(struct nabto_device_thread));
    if (thread == NULL) {
        return NULL;
    }
    return thread;
}

struct nabto_device_mutex* nabto_device_threads_create_mutex(void)
{
    struct nabto_device_mutex* mut = (struct nabto_device_mutex*)np_calloc(1, sizeof(struct nabto_device_mutex));
    if (mut == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&mut->mut, NULL) != 0) {
        np_free(mut);
        return NULL;
    }
    return mut;
}

struct nabto_device_condition* nabto_device_threads_create_condition(void)
{
    struct nabto_device_condition* cond = (struct nabto_device_condition*)np_calloc(1, sizeof(struct nabto_device_condition));
    if (cond == NULL) {
        return NULL;
    }
    if (pthread_cond_init(&cond->cond, NULL) != 0) {
        np_free(cond);
        return NULL;
    }
    return cond;
}

void nabto_device_threads_free_thread(struct nabto_device_thread* thread)
{
    np_free(thread);
}

void nabto_device_threads_free_mutex(struct nabto_device_mutex* mutex)
{
    if (mutex == NULL) {
        return;
    }

    int status = pthread_mutex_destroy(&mutex->mut);
    if (status != 0)
    {
        NABTO_LOG_ERROR(LOG, "Cannot destroy pthread mutex. '%s'", strerror(status));
    }
    np_free(mutex);

}

void nabto_device_threads_free_cond(struct nabto_device_condition* cond)
{
    if (cond == NULL) {
        return;
    }
    int status = pthread_cond_destroy(&cond->cond);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "Cannor destroy pthread condition. '%s'", strerror(status));
    }
    np_free(cond);
}

void nabto_device_threads_join(struct nabto_device_thread* thread)
{
    int status = pthread_join(thread->thread, NULL);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "pthread_join failed. '%s'", strerror(status));
    }
}

void nabto_device_threads_mutex_lock(struct nabto_device_mutex* mutex)
{
    int status = pthread_mutex_lock(&mutex->mut);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "pthread_mutex_lock failed. '%s'", strerror(status));
    }
}

void nabto_device_threads_mutex_unlock(struct nabto_device_mutex* mutex)
{
    int status = pthread_mutex_unlock(&mutex->mut);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "pthread_mutex_unlock failed. '%s'", strerror(status));
    }
}

np_error_code nabto_device_threads_run(struct nabto_device_thread* thread, void *(*run_routine) (void *), void* data)
{
    int ret = pthread_create(&thread->thread, NULL, run_routine, data);
    if (ret != 0)
    {
        NABTO_LOG_TRACE(LOG, "pthread_create failed %d", ret);
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}

void nabto_device_threads_cond_signal(struct nabto_device_condition* cond)
{
    int status = pthread_cond_signal(&cond->cond);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "pthread_cond_signal failed. '%s'", strerror(status));
    }
}

void nabto_device_threads_cond_wait(struct nabto_device_condition* cond,
                                    struct nabto_device_mutex* mut)
{
    int status = pthread_cond_wait(&cond->cond, &mut->mut);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "pthread_cond_wait failed. '%s'", strerror(status));
    }
}

void nabto_device_threads_cond_timed_wait(struct nabto_device_condition* cond,
                                          struct nabto_device_mutex* mut,
                                          uint32_t ms)
{
    struct timespec ts;
    struct timeval tp;
    int status = gettimeofday(&tp, NULL);
    if (status < 0) {
        NABTO_LOG_ERROR(LOG, "gettimeofday failed. '%s'", strerror(status));
        // TODO we cannot really fail.
    }
    // This will wrap when epoch cannot be contained in 64bit, we ignore that and cast
    uint64_t future_ms = tp.tv_usec / 1000 + tp.tv_sec * 1000 + ms;
    ts.tv_nsec = (long)(future_ms % 1000) * 1000000;
    ts.tv_sec = (long)future_ms / 1000;
    status = pthread_cond_timedwait(&cond->cond, &mut->mut, &ts);
    if (status != 0 && status != ETIMEDOUT) {
        NABTO_LOG_ERROR(LOG, "pthread_cond_wait failed. '%s'", strerror(status));
    }
}
