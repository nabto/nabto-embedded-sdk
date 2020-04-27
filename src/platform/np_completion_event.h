#ifndef _NP_COMPLETION_EVENT_H_
#define _NP_COMPLETION_EVENT_H_

#include "np_event_queue.h"
#include "np_error_code.h"

typedef void (*np_completion_event_callback)(const np_error_code ec, void* userData);

struct np_completion_event {
    np_completion_event_callback cb;
    void* userData;
    np_error_code ec;
    struct np_event event;
};

void np_completion_event_init(struct np_platform* pl, struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData);

void np_completion_event_resolve(struct np_completion_event* event, np_error_code ec);

#endif
