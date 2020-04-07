#include "nm_libevent.h"

#include "nm_libevent_dns.h"

#include <platform/np_platform.h>
#include <event2/event.h>

void nm_libevent_init(struct np_platform* pl, struct event_base* eventBase)
{
    nm_libevent_dns_init(pl, eventBase);
}

void nm_libevent_deinit(struct np_platform* pl)
{
    nm_libevent_dns_deinit(pl);
}
