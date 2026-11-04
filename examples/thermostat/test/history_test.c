// Standalone host test for the thermostat history ring buffer.
//
// Build ad hoc with:
//   cc -I ../src history_test.c ../src/thermostat_history.c -lpthread -lm -o history_test
// or enable the guarded THERMOSTAT_BUILD_TESTS cmake option.

#include "thermostat_history.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

static int failures = 0;

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            failures++; \
        } \
    } while (0)

static void test_seed(void)
{
    struct thermostat_history history;
    thermostat_history_init(&history);
    thermostat_history_seed(&history, 21.0, 22.5, THERMOSTAT_HISTORY_SEED_SAMPLES);

    double samples[THERMOSTAT_HISTORY_CAPACITY];
    size_t count = thermostat_history_snapshot(&history, samples, THERMOSTAT_HISTORY_CAPACITY);
    CHECK(count == 288);
    // the newest sample matches the current temperature
    CHECK(fabs(samples[count - 1] - 22.5) < 1e-9);
    // the curve stays near the target
    for (size_t i = 0; i < count; i++) {
        CHECK(fabs(samples[i] - 21.0) < 5.0);
    }
    thermostat_history_deinit(&history);
}

static void test_wraparound(void)
{
    struct thermostat_history history;
    thermostat_history_init(&history);
    for (int i = 0; i < 350; i++) {
        thermostat_history_push(&history, (double)i);
    }
    double samples[THERMOSTAT_HISTORY_CAPACITY];
    size_t count = thermostat_history_snapshot(&history, samples, THERMOSTAT_HISTORY_CAPACITY);
    CHECK(count == 300);
    // the newest 300 samples are kept in order, oldest first
    for (size_t i = 0; i < count; i++) {
        CHECK(samples[i] == (double)(50 + i));
    }
    thermostat_history_deinit(&history);
}

static void test_partial_ordering(void)
{
    struct thermostat_history history;
    thermostat_history_init(&history);
    for (int i = 0; i < 5; i++) {
        thermostat_history_push(&history, 10.0 + i);
    }
    double samples[THERMOSTAT_HISTORY_CAPACITY];
    size_t count = thermostat_history_snapshot(&history, samples, THERMOSTAT_HISTORY_CAPACITY);
    CHECK(count == 5);
    for (size_t i = 0; i < count; i++) {
        CHECK(samples[i] == 10.0 + (double)i);
    }

    // a small snapshot buffer receives the newest samples, oldest first
    double small[3];
    count = thermostat_history_snapshot(&history, small, 3);
    CHECK(count == 3);
    CHECK(small[0] == 12.0 && small[1] == 13.0 && small[2] == 14.0);
    thermostat_history_deinit(&history);
}

int main(void)
{
    test_seed();
    test_wraparound();
    test_partial_ordering();
    if (failures == 0) {
        printf("All history tests passed\n");
        return 0;
    }
    printf("%d history test checks failed\n", failures);
    return 1;
}
