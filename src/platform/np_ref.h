#ifndef NP_REF_H_
#define NP_REF_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Reference counting for objects with asynchronous operations.
 *
 * The lifetime rule for such objects is close -> drain -> free:
 *
 *   1. Every started asynchronous operation completes exactly once, also
 *      when it is aborted.
 *   2. Destroying the object is asynchronous. The owner aborts the
 *      outstanding operations and drops its reference. The memory is
 *      released when the last reference is dropped.
 *   3. The last completion is the last thing which touches the object.
 *
 * An np_ref starts with one reference, the owner's. Each armed completion
 * event which has the object as owner holds a reference (see
 * np_completion_event_init). Other holders take a reference with
 * np_ref_get and drop it with np_ref_put. When the count reaches zero
 * the release function is called, it frees the object.
 *
 * The functions are not thread safe, they must be called from the core
 * context (with the core mutex held).
 */

struct np_ref;

typedef void (*np_ref_release)(struct np_ref* ref);

/**
 * Counts the live reference counted objects of a platform. nabto_device_stop
 * waits for this count to reach zero before the platform is stopped.
 */
struct np_ref_tracker {
    size_t live;
    // Called when live reaches zero, can be NULL.
    void (*empty)(void* userData);
    void* emptyUserData;
};

struct np_ref {
    size_t count;
    np_ref_release release;
    struct np_ref_tracker* tracker;
};

/**
 * Init a reference with count 1, the owner's reference.
 *
 * @param ref  The reference.
 * @param tracker  The tracker which counts the live object, can be NULL.
 * @param release  Called when the count reaches zero.
 */
void np_ref_init(struct np_ref* ref, struct np_ref_tracker* tracker, np_ref_release release);

/**
 * Get the object which contains the reference, e.g. in a release function:
 *   struct foo* f = np_ref_container(ref, struct foo, ref);
 */
#define np_ref_container(ref, type, member) ((type*)((char*)(ref) - offsetof(type, member)))

void np_ref_get(struct np_ref* ref);

/**
 * Drop a reference. If it was the last reference, the release function
 * is called. The object must not be used by the caller after this call.
 */
void np_ref_put(struct np_ref* ref);

/**
 * Report a broken lifetime contract, e.g. a completion event which is
 * resolved twice or deinitialized while an operation is outstanding.
 * The violation is logged as an error. If the SDK is built with
 * NABTO_DEVICE_LIFETIME_CHECKS it aborts the program.
 */
void np_lifetime_violation(const char* what);

/**
 * @return the number of lifetime contract violations reported in this
 * process. Used by tests.
 */
size_t np_lifetime_violation_count(void);

/**
 * Called on each lifetime contract violation if set. Used by tests to
 * report where the violation happened.
 */
extern void (*np_lifetime_violation_hook)(const char* what);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
