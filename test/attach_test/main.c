#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/nm_unix_timestamp.h>
#include <modules/crypto/nm_dtls.h>
#include <modules/dns/nm_unix_dns.h>
#include <platform/np_ip_address.h>
#include <core/nc_connection.h>
#include <core/nc_attacher.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

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
    nm_dtls_init(&pl);
    nm_unix_ts_init(&pl);
    nm_unix_dns_init(&pl);
    nc_connection_init(&pl);
  
    np_log.log = &nm_unix_log;
    np_log.log_buf = &nm_unix_log_buf;
    struct test_context data;
    data.data = 42;
    nc_attacher_async_attach(&pl, attachedCb, &data);
    while (true) {
        np_event_queue_execute_all(&pl);
        nm_epoll_wait();
    }

    exit(0);
}
