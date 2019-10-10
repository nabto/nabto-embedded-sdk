#include <api/nabto_platform.h>

#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/epoll/nm_epoll.h>
#include <modules/mdns/nm_mdns.h>

struct nm_epoll_context epoll;

void nabto_device_init_platform_modules(struct np_platform* pl)
{
    np_communication_buffer_init(pl);
    nm_epoll_init(&epoll, pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
}

int nabto_device_platform_inf_wait()
{
    return nm_epoll_inf_wait(&epoll);
}

void nabto_device_platform_read(int nfds)
{
    nm_epoll_read(&epoll, nfds);
}

void nabto_device_platform_close(struct np_platform* pl)
{
    nm_epoll_close(&epoll);
}

void nabto_device_platform_signal(struct np_platform* pl)
{
    nm_epoll_break_wait(&epoll);
}

bool nabto_device_platform_finished() {
    return nm_epoll_finished(&epoll);
}
