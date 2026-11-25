#include "np_ref.h"

#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

void np_ref_init(struct np_ref* ref, struct np_ref_tracker* tracker, np_ref_release release)
{
    ref->count = 1;
    ref->release = release;
    ref->tracker = tracker;
    if (tracker != NULL) {
        tracker->live++;
    }
}

void np_ref_get(struct np_ref* ref)
{
    if (ref->count == 0) {
        np_lifetime_violation("reference taken on a released object");
        return;
    }
    ref->count++;
}

void np_ref_put(struct np_ref* ref)
{
    if (ref->count == 0) {
        np_lifetime_violation("reference dropped on a released object");
        return;
    }
    ref->count--;
    if (ref->count > 0) {
        return;
    }
    // The release function frees the object which contains ref.
    struct np_ref_tracker* tracker = ref->tracker;
    ref->release(ref);
    if (tracker != NULL) {
        tracker->live--;
        if (tracker->live == 0 && tracker->empty != NULL) {
            tracker->empty(tracker->emptyUserData);
        }
    }
}

// Only used for diagnostics, an exact count is not needed if violations
// happen on more than one thread at once.
static size_t violationCount = 0;

void (*np_lifetime_violation_hook)(const char* what) = NULL;

void np_lifetime_violation(const char* what)
{
    violationCount++;
    if (np_lifetime_violation_hook != NULL) {
        np_lifetime_violation_hook(what);
    }
    NABTO_LOG_ERROR(LOG, "Lifetime contract violation: %s", what);
#if defined(NABTO_DEVICE_LIFETIME_CHECKS)
    abort();
#endif
}

size_t np_lifetime_violation_count(void)
{
    return violationCount;
}
