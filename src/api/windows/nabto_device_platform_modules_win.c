#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/timestamp/win/nm_win_timestamp.h>
#include <modules/libevent/nm_libevent.h>

struct nm_libevent_context libeventContext;

np_error_code nabto_device_init_platform_modules(struct np_platform* pl)
{
    np_communication_buffer_init(pl);
    nm_libevent_init(pl);
//    nm_win_udp_select_init(pl);
    nm_win_ts_init(pl);
//    nm_win_dns_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
    return NABTO_EC_OK;
}

void nabto_device_deinit_platform_modules(struct np_platform* pl)
{
    nm_random_deinit(pl);
}
