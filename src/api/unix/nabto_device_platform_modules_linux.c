#include <api/nabto_platform.h>

#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/udp/epoll/nm_epoll.h>

void nabto_device_init_platform_modules(struct np_platform* pl)
{
    np_communication_buffer_init(pl);
    nm_unix_udp_epoll_init(pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
}

int nabto_device_platform_inf_wait()
{
    return nm_epoll_inf_wait();
}

void nabto_device_platform_read(int nfds)
{
    nm_epoll_read(nfds);
}
