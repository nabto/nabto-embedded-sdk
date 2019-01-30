#include <platform/np_platform.h>

#include <platform/np_logging.h>

#include <modules/communication_buffer/nm_unix_communication_buffer.h>

#include <string.h>

void nabto_device_init_platform(struct np_platform* pl)
{
    np_platform_init(pl);
    np_log_init();
}

void nabto_device_init_platform_modules(struct np_platform* pl, const char* devicePublicKey, const char* devicePrivateKey)
{
    np_access_control_init(pl);
    nm_unix_comm_buf_init(pl);
    np_udp_init(pl);
    np_dtls_cli_init(pl, devicePublicKey, strlen((const char*)devicePublicKey),
                     devicePrivateKey, strlen((const char*)devicePrivateKey));
    np_dtls_srv_init(pl, devicePublicKey, strlen((const char*)devicePublicKey),
                     devicePrivateKey, strlen((const char*)devicePrivateKey));
    np_ts_init(pl);
    np_dns_init(pl);
}
