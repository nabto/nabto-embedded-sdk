#include <platform/np_platform.h>

#include <platform/np_logging.h>

#include <string.h>

void nabto_device_init_platform(struct np_platform* pl)
{
    np_platform_init(pl);
    np_log_init();
}

void nabto_device_init_platform_modules(struct np_platform* pl, const char* devicePublicKey, const char* devicePrivateKey)
{
    np_access_control_init(pl);
    np_communication_buffer_init(pl);
    np_udp_init(pl);
    np_dtls_cli_init(pl, (const uint8_t*)devicePublicKey, strlen((const char*)devicePublicKey),
                     (const uint8_t*)devicePrivateKey, strlen((const char*)devicePrivateKey));
    np_dtls_srv_init(pl, (const uint8_t*)devicePublicKey, strlen((const char*)devicePublicKey),
                     (const uint8_t*)devicePrivateKey, strlen((const char*)devicePrivateKey));
    np_ts_init(pl);
    np_dns_init(pl);
}
