#include <platform/np_platform.h>

#include <modules/udp/select_win/nm_select_win.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/win/nm_win_timestamp.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/win/nm_win_dns.h>
#include <modules/access_control/nm_access_control.h>


void nabto_device_init_platform(struct np_platform* pl)
{
    np_platform_init(pl);
    nm_unix_log_init();
}

void nabto_device_init_platform_modules(struct np_platform* pl, const char* devicePublicKey, const char* devicePrivateKey)
{
    nm_access_control_init(pl);
    nm_unix_comm_buf_init(pl);
    nm_select_win_init(pl);
    nm_dtls_init(pl, devicePublicKey, strlen((const char*)devicePublicKey),
                 devicePrivateKey, strlen((const char*)devicePrivateKey));
    nm_dtls_srv_init(pl, devicePublicKey, strlen((const char*)devicePublicKey),
                     devicePrivateKey, strlen((const char*)devicePrivateKey));
    nm_win_ts_init(pl);
    nm_win_dns_init(pl);
}
