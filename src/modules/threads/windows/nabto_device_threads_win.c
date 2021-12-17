#include <api/nabto_device_threads.h>

#include <platform/np_logging.h>

#include <winsock2.h>
#include <windows.h>
#include <string.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

struct nabto_device_thread {
    HANDLE thread;
    void *(*run_routine) (void *);
    void* data;
};

struct nabto_device_mutex {
    SRWLOCK mutex;
};

struct nabto_device_condition {
    CONDITION_VARIABLE cond;
};

struct nabto_device_thread* nabto_device_threads_create_thread()
{
    struct nabto_device_thread* thread = (struct nabto_device_thread*)calloc(1, sizeof(struct nabto_device_thread));
    if (thread == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate thread");
        return NULL;
    }
    NABTO_LOG_TRACE(LOG, "Allocated thread: %u", thread);
    return thread;
}

struct nabto_device_mutex* nabto_device_threads_create_mutex()
{
    struct nabto_device_mutex* mutex = (struct nabto_device_mutex*)calloc(1, sizeof(struct nabto_device_mutex));
    if (mutex == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate mutex");
        return NULL;
    }
    InitializeSRWLock(&mutex->mutex);
    return mutex;
}

struct nabto_device_condition* nabto_device_threads_create_condition()
{
    struct nabto_device_condition* cond = (struct nabto_device_condition*)calloc(1, sizeof(struct nabto_device_condition));
    if (cond == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate condition");
        return NULL;
    }
    InitializeConditionVariable(&cond->cond);
    return cond;
}

void nabto_device_threads_free_thread(struct nabto_device_thread* thread)
{
    NABTO_LOG_TRACE(LOG, "freeing thread: %u", thread);
    CloseHandle(thread->thread);
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
    WaitForSingleObject(thread->thread, INFINITE);
}

void nabto_device_threads_mutex_lock(struct nabto_device_mutex* mutex)
{
    AcquireSRWLockExclusive(&mutex->mutex);
}

void nabto_device_threads_mutex_unlock(struct nabto_device_mutex* mutex)
{
    ReleaseSRWLockExclusive(&mutex->mutex);
}

DWORD WINAPI nabto_device_threads_func(void* data) {
    struct nabto_device_thread* ctx = (struct nabto_device_thread*)data;
    ctx->run_routine(ctx->data);
    return 0;
}

np_error_code nabto_device_threads_run(struct nabto_device_thread* thread,
                                       void *(*run_routine) (void *), void* data)
{
    NABTO_LOG_TRACE(LOG, "creating thread: %u", thread);
    thread->run_routine = run_routine;
    thread->data = data;
    thread->thread = CreateThread(NULL, 0, nabto_device_threads_func, thread, 0, NULL);
    if (!thread->thread) {
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}

void nabto_device_threads_cond_signal(struct nabto_device_condition* cond)
{
    WakeConditionVariable(&cond->cond);
}

void nabto_device_threads_cond_wait(struct nabto_device_condition* cond,
                                    struct nabto_device_mutex* mut)
{
    SleepConditionVariableSRW(&cond->cond, &mut->mutex, INFINITE, 0);
}

void nabto_device_threads_cond_timed_wait(struct nabto_device_condition* cond,
                                          struct nabto_device_mutex* mut,
                                          uint32_t ms)
{
    SleepConditionVariableSRW(&cond->cond, &mut->mutex, ms, 0);
}
