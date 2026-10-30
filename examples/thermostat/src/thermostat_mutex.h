#ifndef THERMOSTAT_MUTEX_H_
#define THERMOSTAT_MUTEX_H_

#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION thermostat_mutex;
static inline void thermostat_mutex_init(thermostat_mutex* mutex) { InitializeCriticalSection(mutex); }
static inline void thermostat_mutex_destroy(thermostat_mutex* mutex) { DeleteCriticalSection(mutex); }
static inline void thermostat_mutex_lock(thermostat_mutex* mutex) { EnterCriticalSection(mutex); }
static inline void thermostat_mutex_unlock(thermostat_mutex* mutex) { LeaveCriticalSection(mutex); }
#else
#include <pthread.h>
typedef pthread_mutex_t thermostat_mutex;
static inline void thermostat_mutex_init(thermostat_mutex* mutex) { pthread_mutex_init(mutex, NULL); }
static inline void thermostat_mutex_destroy(thermostat_mutex* mutex) { pthread_mutex_destroy(mutex); }
static inline void thermostat_mutex_lock(thermostat_mutex* mutex) { pthread_mutex_lock(mutex); }
static inline void thermostat_mutex_unlock(thermostat_mutex* mutex) { pthread_mutex_unlock(mutex); }
#endif

#endif
