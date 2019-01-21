#include "nabto_device_threads.h"

#include <platform/np_logging.h>

#include <winsock2.h>
#include <windows.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_API

//TODO: switch to SRW locks
struct nabto_device_thread {
	HANDLE thread;
	void *(*run_routine) (void *);
	void* data;
};

struct nabto_device_mutex {
	HANDLE mutex;
};

struct nabto_device_condition {
    int i;
};

struct nabto_device_thread* nabto_device_threads_create_thread()
{
	struct nabto_device_thread* thread = (struct nabto_device_thread*)malloc(sizeof(struct nabto_device_thread));
	if (thread == NULL) {
		NABTO_LOG_ERROR(LOG, "Failed to allocate thread");
		return NULL;
	}
	return thread;
}

struct nabto_device_mutex* nabto_device_threads_create_mutex()
{
	struct nabto_device_mutex* mutex = (struct nabto_device_mutex*)malloc(sizeof(struct nabto_device_mutex));
	if (mutex == NULL) {
		NABTO_LOG_ERROR(LOG, "Failed to allocate mutex");
		return NULL;
	}
	mutex->mutex = CreateMutex(NULL, FALSE, NULL);
	if (mutex->mutex == NULL) {
		NABTO_LOG_ERROR(LOG, "Failed to create mutex");
		free(mutex);
		return NULL;
	}
	return mutex;
}

struct nabto_device_condition* nabto_device_threads_create_cond()
{
	struct nabto_device_condition* cond = (struct nabto_device_condition*)malloc(sizeof(struct nabto_device_condition));
	if (cond == NULL) {
		NABTO_LOG_ERROR(LOG, "Failed to allocate condition");
		return NULL;
	}
	return cond;
}

void nabto_device_threads_free_thread(struct nabto_device_thread* thread)
{
	CloseHandle(thread->thread);
	free(thread);
}

void nabto_device_threads_free_mutex(struct nabto_device_mutex* mutex)
{
	CloseHandle(mutex->mutex);
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
	WaitForSingleObject(mutex->mutex, INFINITE);
}

void nabto_device_threads_mutex_unlock(struct nabto_device_mutex* mutex)
{
	ReleaseMutex(mutex->mutex);
}

DWORD WINAPI nabto_device_threads_func(void* data) {
	struct nabto_device_thread* ctx = (struct nabto_device_thread*)data;
	ctx->run_routine(ctx->data);
	return 0;
}

np_error_code nabto_device_threads_run(struct nabto_device_thread* thread,
                                       void *(*run_routine) (void *), void* data)
{
	thread->thread = CreateThread(NULL, 0, nabto_device_threads_func, thread, 0, NULL);
	if (!thread->thread) {
		return NABTO_EC_FAILED;
	}
	return NABTO_EC_OK;
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

