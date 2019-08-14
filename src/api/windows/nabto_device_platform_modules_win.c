#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/win/nm_win_dns.h>
#include <modules/timestamp/win/nm_win_timestamp.h>
#include <modules/udp/select_win/nm_select_win.h>

void nabto_device_init_platform_modules(struct np_platform* pl)
{
    np_communication_buffer_init(pl);
    nm_win_udp_select_init(pl);
    nm_win_ts_init(pl);
    nm_win_dns_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
}
