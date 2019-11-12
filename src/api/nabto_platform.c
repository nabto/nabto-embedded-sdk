
#include "nabto_platform.h"

#include <platform/np_platform.h>

#include <platform/np_logging.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/logging/api/nm_api_logging.h>


#include <string.h>

void nabto_device_init_platform(struct np_platform* pl)
{
    np_platform_init(pl);
    nm_api_log_init();
}
