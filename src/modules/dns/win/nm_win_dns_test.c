#include "nm_win_dns.h"

#include <platform/np_platform.h>
#include <platform/np_logging.h>

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
const char* host = "www.google.com";
void resolved(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    NABTO_LOG_ERROR(0, "Host resolved to: %u.%u.%u.%u", rec[0].v4.addr[0], rec[0].v4.addr[1], rec[0].v4.addr[2], rec[0].v4.addr[3]);
    WSACleanup();
    //exit(0);
}

int main()
{
    WSADATA wsaData;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    struct np_platform pl;
    np_platform_init(&pl);
    np_log_init();
    np_ts_init(&pl);
    np_dns_init(&pl);

    np_error_code ec = nm_win_dns_resolve(&pl, host, &resolved, NULL);
    while(1) {
        np_event_queue_execute_all(&pl);
    }
}
