#ifndef THERMOSTAT_HISTORY_H_
#define THERMOSTAT_HISTORY_H_

#include "thermostat_mutex.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * In memory ring buffer with room temperature samples. The buffer holds a
 * sample each 5 minutes, 288 samples covers 24 hours, the capacity has a bit
 * of headroom. The buffer is not persisted.
 */

#define THERMOSTAT_HISTORY_CAPACITY 300
#define THERMOSTAT_HISTORY_INTERVAL_SECONDS 300
#define THERMOSTAT_HISTORY_SEED_SAMPLES 288

struct thermostat_history {
    double samples[THERMOSTAT_HISTORY_CAPACITY];
    size_t head;
    size_t count;
    thermostat_mutex mutex;
};

void thermostat_history_init(struct thermostat_history* history);
void thermostat_history_deinit(struct thermostat_history* history);

/**
 * Fill the buffer with sampleCount synthetic samples. The samples form a
 * plausible smooth curve around the target temperature which ends exactly at
 * endTemperature.
 */
void thermostat_history_seed(struct thermostat_history* history, double target, double endTemperature, size_t sampleCount);

/**
 * Push a sample, overwriting the oldest sample if the buffer is full.
 */
void thermostat_history_push(struct thermostat_history* history, double sample);

/**
 * Copy up to bufferSize samples into buffer ordered oldest first, newest
 * last. Returns the number of samples copied.
 */
size_t thermostat_history_snapshot(struct thermostat_history* history, double* buffer, size_t bufferSize);

#endif
