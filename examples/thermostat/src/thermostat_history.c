#include "thermostat_history.h"

#include <math.h>
#include <string.h>
#include <stdint.h>

void thermostat_history_init(struct thermostat_history* history)
{
    memset(history, 0, sizeof(struct thermostat_history));
    pthread_mutex_init(&history->mutex, NULL);
}

void thermostat_history_deinit(struct thermostat_history* history)
{
    pthread_mutex_destroy(&history->mutex);
}

void thermostat_history_push(struct thermostat_history* history, double sample)
{
    pthread_mutex_lock(&history->mutex);
    history->samples[history->head] = sample;
    history->head = (history->head + 1) % THERMOSTAT_HISTORY_CAPACITY;
    if (history->count < THERMOSTAT_HISTORY_CAPACITY) {
        history->count++;
    }
    pthread_mutex_unlock(&history->mutex);
}

size_t thermostat_history_snapshot(struct thermostat_history* history, double* buffer, size_t bufferSize)
{
    pthread_mutex_lock(&history->mutex);
    size_t count = history->count;
    if (count > bufferSize) {
        count = bufferSize;
    }
    size_t start = (history->head + THERMOSTAT_HISTORY_CAPACITY - count) % THERMOSTAT_HISTORY_CAPACITY;
    for (size_t i = 0; i < count; i++) {
        buffer[i] = history->samples[(start + i) % THERMOSTAT_HISTORY_CAPACITY];
    }
    pthread_mutex_unlock(&history->mutex);
    return count;
}

void thermostat_history_seed(struct thermostat_history* history, double target, double endTemperature, size_t sampleCount)
{
    double curve[THERMOSTAT_HISTORY_CAPACITY];
    if (sampleCount == 0) {
        return;
    }
    if (sampleCount > THERMOSTAT_HISTORY_CAPACITY) {
        sampleCount = THERMOSTAT_HISTORY_CAPACITY;
    }

    // Deterministic small variation from a linear congruential generator
    // combined with a slow drift around the target temperature.
    uint32_t lcg = 0x12345678;
    for (size_t i = 0; i < sampleCount; i++) {
        lcg = lcg * 1664525u + 1013904223u;
        double noise = (((double)((lcg >> 16) & 0x7fff) / 32767.0) - 0.5) * 0.2;
        double phase = (2.0 * 3.14159265358979323846 * (double)i) / (double)sampleCount;
        double drift = 0.7 * sin(2.0 * phase) + 0.2 * sin(5.0 * phase);
        curve[i] = target + drift + noise;
    }

    // Correct the curve linearly such that the newest sample matches the
    // current temperature exactly while keeping the curve smooth.
    double correction = endTemperature - curve[sampleCount - 1];
    for (size_t i = 0; i < sampleCount; i++) {
        double weight = (sampleCount > 1) ? ((double)i / (double)(sampleCount - 1)) : 1.0;
        thermostat_history_push(history, curve[i] + (correction * weight));
    }
}
