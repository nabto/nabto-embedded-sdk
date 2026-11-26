#ifndef NP_COMPLETION_EVENT_H_
#define NP_COMPLETION_EVENT_H_

#include "interfaces/np_event_queue.h"
#include "np_error_code.h"
#include "np_ref.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*np_completion_event_callback)(const np_error_code ec, void* userData);

/**
 * A completion event is given to an asynchronous operation, which
 * resolves it exactly once when the operation completes. The callback is
 * then called from the event queue.
 *
 * Contract:
 *
 *   - The operation which takes the event arms it with
 *     np_completion_event_arm, and then resolves it exactly once, also if
 *     it is aborted or the resource it belongs to is destroyed. The
 *     platform wrappers (np_udp_*, np_tcp_*, np_dns_*, and
 *     nabto_device_platform_async_close for nabto_device_platform_close)
 *     arm events on behalf of the platform integration. A function which only passes
 *     the event on to another operation does not arm it. A function which
 *     returns an error does not take the event, so it does not arm it.
 *     np_completion_event_disarm undoes an arm if an operation fails
 *     after the event was armed but before it was taken.
 *   - The event is disarmed when the callback is called. It must not be
 *     deinitialized or reinitialized while it is armed.
 *   - Every event has an owner, the object the event belongs to, given to
 *     np_completion_event_init. The armed event holds a reference to the
 *     owner which is dropped after the callback has returned, so the owner
 *     is not freed while the operation is outstanding. Objects which live as
 *     long as the device use the device's reference (nc_device_context.ref).
 *
 * Breaking the contract is reported with np_lifetime_violation.
 *
 * Platform integrations only resolve completion events, they never arm,
 * deinit or reinit them. np_completion_event_resolve can be called from any
 * thread.
 */
struct np_completion_event {
    bool initialized;
    bool armed;
    struct np_event_queue eq;
    np_completion_event_callback cb;
    void* userData;
    np_error_code ec;
    struct np_event* event;
    struct np_ref* owner;
};

/**
 * Init a completion event.
 *
 * @param eq  The event queue.
 * @param completionEvent  The completion event to initialize.
 * @param cb  The callback to call when the completion events is resolved.
 * @param userData  The userData to give to the callback.
 * @param owner  The object the event belongs to. While the event is armed
 *               it holds a reference to the owner.
 */
np_error_code np_completion_event_init(struct np_event_queue* eq, struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData, struct np_ref* owner);

/**
 * Reinitialize a completion event. The event must not be armed.
 */
void np_completion_event_reinit(struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData);

/**
 * Deinitialize a completion event. The event must not be armed.
 *
 * @param completionEvent  The completionEvent
 */
void np_completion_event_deinit(struct np_completion_event* completionEvent);

/**
 * Resolve a completion event.
 *
 * The completion event is resolved from the internal event queue.
 *
 * @param completionEvent  The completion event to resolve.
 * @param ec  The error code
 */
void np_completion_event_resolve(struct np_completion_event* completionEvent, np_error_code ec);

/**
 * Arm the completion event. Called by the operation which takes the event
 * and later resolves it.
 */
void np_completion_event_arm(struct np_completion_event* completionEvent);

/**
 * Disarm an armed completion event without resolving it.
 */
void np_completion_event_disarm(struct np_completion_event* completionEvent);

/**
 * @return true iff the event is armed, i.e. its operation is outstanding.
 */
bool np_completion_event_is_armed(const struct np_completion_event* completionEvent);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
