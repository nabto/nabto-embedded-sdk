#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/nm_unix_timestamp.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dns/nm_unix_dns.h>
#include <platform/np_ip_address.h>
#include <core/nc_connection.h>
#include <core/nc_attacher.h>
#include <core/nc_client_connect.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

const char* appVer = "0.0.1";
const char* appName = "Weather_app";
const unsigned char devicePrivateKey[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEII2ifv12piNfHQd0kx/8oA2u7MkmnQ+f8t/uvHQvr5wOoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEY1JranqmEwvsv2GK5OukVPhcjeOW+MRiLCpy7Xdpdcdc7he2nQgh\r\n"
"0+aTVTYvHZWacrSTZFQjXljtQBeuJR/Gsg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const unsigned char devicePublicKey[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBaTCCARCgAwIBAgIJAOR5U6FNgvivMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMM\r\n"
"BW5hYnRvMB4XDTE4MDgwNzA2MzgyN1oXDTQ4MDczMDA2MzgyN1owEDEOMAwGA1UE\r\n"
"AwwFbmFidG8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARjUmtqeqYTC+y/YYrk\r\n"
"66RU+FyN45b4xGIsKnLtd2l1x1zuF7adCCHT5pNVNi8dlZpytJNkVCNeWO1AF64l\r\n"
"H8ayo1MwUTAdBgNVHQ4EFgQUjq36vzjxAQ7I8bMejCf1/m0eQ2YwHwYDVR0jBBgw\r\n"
"FoAUjq36vzjxAQ7I8bMejCf1/m0eQ2YwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO\r\n"
"PQQDAgNHADBEAiBF98p5zJ+98XRwIyvCJ0vcHy/eJM77fYGcg3J/aW+lIgIgMMu4\r\n"
"XndF4oYF4h6yysELSJfuiamVURjo+KcM1ixwAWo=\r\n"
"-----END CERTIFICATE-----\r\n";

struct test_context {
    int data;
};
struct np_platform pl;

void attachedCb(const np_error_code ec, void* data) {
    if (ec == NABTO_EC_OK) {
        NABTO_LOG_INFO(0, "Received attached callback with NABTO_EC_OK");
    } else {
        NABTO_LOG_INFO(0, "Received attached callback with ERROR %u", ec);
        exit(1);
    }
}


int main() {
    np_platform_init(&pl);
    nm_unix_comm_buf_init(&pl);
    nm_epoll_init(&pl);
    nm_dtls_init(&pl, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));
    nm_unix_ts_init(&pl);
    nm_unix_dns_init(&pl);
    nc_connection_init(&pl);
    nc_client_connect_init(&pl);
  
    np_log.log = &nm_unix_log;
    np_log.log_buf = &nm_unix_log_buf;
    struct test_context data;
    data.data = 42;
    nc_attacher_async_attach(&pl, appName, strlen(appName), appVer, strlen(appVer), attachedCb, &data);
    while (true) {
        np_event_queue_execute_all(&pl);
        nm_epoll_wait();
    }

    exit(0);
}
