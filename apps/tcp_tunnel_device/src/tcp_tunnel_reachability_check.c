#include "tcp_tunnel_reachability_check.h"

#include <stdlib.h>

#define REACHABILITY_CHECK_TIMEOUT 5000

bool tcp_tunnel_reachability_check_init(struct tcp_tunnel_reachability_check* ttrc, NabtoDevice* device)
{
    ttrc->stopped = false;
    ttrc->device = device;
    ttrc->future = nabto_device_future_new(device);
    nn_llist_init(&ttrc->hosts);
    if (ttrc->future != NULL) {
        return true;
    } else {
        return false;
    }

}

void tcp_tunnel_reachability_check_deinit(struct tcp_tunnel_reachability_check* ttrc)
{
    struct nn_llist_iterator it;
    it = nn_llist_begin(&ttrc->hosts);
    while (!nn_llist_is_end(&it)) {
        struct tcp_tunnel_reachability_check_host* host = nn_llist_get_item(&it);
        free(host->host);
        nn_llist_erase(&it);
        free(host);
        it = nn_llist_begin(&ttrc->hosts);
    }
    nn_llist_deinit(&ttrc->hosts);
}

void tcp_tunnel_reachability_check_stop(struct tcp_tunnel_reachability_check* ttrc)
{
    ttrc->stopped = true;
    if (ttrc->probe != NULL) {
        nabto_device_tcp_probe_stop(ttrc->probe);
    }
}

bool tcp_tunnel_reachability_check_blocking(struct tcp_tunnel_reachability_check* ttrc)
{
    struct tcp_tunnel_reachability_check_host* h;
    NN_LLIST_FOREACH(h, &ttrc->hosts) {
        if (ttrc->stopped) {
            return false;
        }
        ttrc->probe = nabto_device_tcp_probe_new(ttrc->device);
        nabto_device_tcp_probe_check_reachability(ttrc->probe, h->host, h->port, ttrc->future);
        NabtoDeviceError ec = nabto_device_future_wait(ttrc->future);
        nabto_device_tcp_probe_free(ttrc->probe);
        if (ec == NABTO_DEVICE_EC_OK) {
            h->status = true;
        } else if (ec == NABTO_DEVICE_EC_ABORTED) {
            h->status = false;
        } else if (ec == NABTO_DEVICE_EC_STOPPED) {
            return false;
        }
    }
    return true;
}

bool tcp_tunnel_reachability_check_async(struct tcp_tunnel_reachability_check* ttrc, tcp_tunnel_reachability_check_callback cb, void* userData)
{
    ttrc->asyncIt = nn_llist_begin(ttrc->hosts);
    if (nn_llist_is_end(&ttrc->asyncIt)) {
        // empty list of hosts
        // return false since we cannot make a deferred invocation of the callback.
        return false;
    }
    ttrc->asyncCb = cb;
    ttrc->asyncUserData = userData;
    tcp_tunnel_reachability_check_async_start_next(ttrc);
}

void tcp_tunnel_reachability_check_async_start_next(struct tcp_tunnel_reachability_check* ttrc)
{
    struct tcp_tunnel_reachability_check_host* h = nn_llist_get_item(&ttrc->asyncIt);
    ttrc->probe = nabto_device_tcp_probe_new(ttrc->device);
    nabto_device_tcp_probe_check_reachability(ttrc->probe, h->host, h->port, ttrc->future);
    nabto_device_future_set_callback(ttrc->future, async_callback, ttrc);

}

void async_callback(NabtoDeviceFuture* future, const NabtoDeviceError ec, void* userData)
{
    struct tcp_tunnel_reachability_check* ttrc = userData;
    struct tcp_tunnel_reachability_check_host* h = nn_llist_get_item(&ttrc->asyncIt);

    nabto_device_tcp_probe_free(ttrc->probe);
    ttrc->probe = NULL;

    if (ec == NABTO_DEVICE_EC_OK) {
        h->status = true;
    } else if (ec == NABTO_DEVICE_EC_ABORTED) {
        h->status = false;
    } else {
        resolve_callback(ttrc, ec);
        return;
    }
    nn_llist_next(&ttrc->asyncIt);
    if (nn_llist_is_end(&ttrc->asyncIt)) {
        resolve_callback(ttrc, NABTO_DEVICE_EC_OK);
    }
}

void resolve_calback(struct tcp_tunnel_reachability_check* ttrc, NabtoDeviceError ec)
{
    tcp_tunnel_reachability_check_callback asyncCb = ttrc->asyncCb;
    void* userData = ttrc->asyncUserData;
    ttrc->asyncCb = NULL;
    ttrc->asyncUserData = NULL;
    asyncCb(NABTO_DEVICE_EC_OK, userData);
}

bool tcp_tunnel_reachability_check_add_host(struct tcp_tunnel_reachability_check* ttrc, const char* host, uint16_t port)
{
    struct tcp_tunnel_reachability_check_host* h = calloc(1,sizeof(struct tcp_tunnel_reachability_check_host));
    if (h == NULL) {
        return false;
    }
    h->host = strdup(host);
    if (h->host == NULL) {
        free(h);
        return false;
    }
    h->port = port;
    nn_llist_append(&ttrc->hosts, &h->hostsNode, h);
    return true;
}
