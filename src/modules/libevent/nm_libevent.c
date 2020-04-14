#include "nm_libevent.h"

#include "nm_libevent_dns.h"
#include "nm_libevent_udp.h"
#include "nm_libevent_timestamp.h"

#include <platform/np_platform.h>
#include <event2/event.h>

void nm_libevent_init(struct np_platform* pl, struct nm_libevent_context* ctx, struct event_base* eventBase)
{
    ctx->eventBase = eventBase;
    ctx->pl = pl;
    ctx->recvBuffer = pl->buf.allocate();
    nm_libevent_dns_init(pl, ctx->eventBase);
    nm_libevent_udp_init(pl, ctx);
    nm_libevent_timestamp_init(eventBase, pl);
}

void nm_libevent_deinit(struct nm_libevent_context* ctx)
{
    struct np_platform* pl = ctx->pl;

    nm_libevent_udp_deinit(pl);
    nm_libevent_dns_deinit(pl);

    pl->buf.free(ctx->recvBuffer);
}
