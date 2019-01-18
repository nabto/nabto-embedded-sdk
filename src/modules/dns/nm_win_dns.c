#include "nm_unix_dns.h"

#include <platform/np_logging.h>
#include <platform/np_error_code.h>

#include <winsock2.h>
#include <windows.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_DNS

struct nm_win_dns_ctx {
	struct np_timed_event ev;
    const char* host;
	size_t recSize;
	np_dns_reslove_callback cb;
	np_error_code ec;
	void* data;
	bool resolverIsRunning;
	struct np_platform* pl;
	struct np_ip_address ips[NP_DNS_RESOLVED_IPS_MAX];
};

void nm_win_dns_check_resolved(const np_error_code ec, void* data);

DWORD WINAPI resolver_thread(LPVOID data) {
    struct nm_win_dns_ctx* ctx = (struct nm_win_dns_ctx*)data;

    struct hostent* he = gethostbyname(state->id);
    if (he == 0) {
        state->ec = NABTO_EC_FAILED;
    } else if (he->h_addrtype == AF_INET && he->h_length == 4) {
        uint8_t i;
        ctx->ec = NABTO_EC_OK;
        for (i = 0; i < NP_DNS_RESOLVED_IPS_MAX; i++) {
            uint8_t* addr = (uint8_t*)he->h_addr_list[i];
            if (addr == NULL) {
                break;
            }
			ctx->recSize++;
			ctx->ips[i].type = NABTO_IPV4
			memcpy(ctx->ips[i].v4.addr, addr, 4);
        }
    } else if (he->h_addrtype == AF_INET6 && he->h_length == 16) {
        uint8_t i;
        ctx->ec = NABTO_EC_OK;
        for (i = 0; i < NP_DNS_RESOLVED_IPS_MAX; i++) {
            uint8_t* addr = (uint8_t*)he->h_addr_list[i];
            if (addr == NULL) {
                break;
            }
			ctx->recSize++;
			ctx->ips[i].type = NABTO_IPV6
			memcpy(ctx->ips[i].v4.addr, addr, 16);
        }
	}
    ctx->resolverIsRunning = false;
    return 0;
}

void nm_win_dns_init(struct np_platform* pl)
{
	pl->dns.async_resolve = &nm_win_dns_resolve;
}

np_error_code nm_win_dns_resolve(struct  np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data) {
    // host isn't a dotted IP, so resolve it through DNS
	struct nm_win_dns_ctx* ctx = (struct nm_win_dns_ctx*)malloc(sizeof(struct nm_win_dns_ctx));
	if (!ctx) {
		NABTO_LOG_ERROR(LOG, "Failed to allocate context");
		return NABTO_EC_FAILED;
	}
    memset(ctx, 0, sizeof(struct nm_win_dns_ctx));
	ctx->resolverIsRunning = true;
	ctx->data = data;
	ctx->host = host;
	ctx->cb = cb;
	ctx->pl = pl;
	ctx->ec = NABTO_EC_OPERATION_IN_PROGRESS;
    HANDLE thread;
    thread = CreateThread(NULL, 0, resolver_thread, &ctx, 0, NULL);
    if (!thread) {
		NABTO_LOG_ERROR(LOG, "Failed to create resolver thread");
		free(ctx);
        return NABTO_EC_FAILED;
    }
	np_event_queue_post_timed_event(ctx->pl, &ctx->ev, 50, &nm_win_dns_check_resolved, data);
    return NABTO_EC_OK;
}

void nm_win_dns_check_resolved(const np_error_code ec, void* data) {
	struct nm_win_dns_ctx* ctx = (struct nm_win_dns_ctx*)data;
    if (ctx->resolverIsRunning) {
		np_event_queue_post_timed_event(ctx->pl, &ctx->ev, 50, &nm_win_dns_check_resolved, data);
        return;
    } else {
		ctx->cb(ctx->ec, ctx->ips, ctx->recSize, ctx->data);
		free(ctx);
		return;
	}
}
    
