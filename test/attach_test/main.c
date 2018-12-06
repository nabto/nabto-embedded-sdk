#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/nm_unix_timestamp.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/nm_unix_dns.h>
#include <platform/np_ip_address.h>
#include <core/nc_attacher.h>
#include <core/nc_client_connect.h>
#include <core/nc_client_connect_dispatch.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

const char* appVer = "0.0.1";
const char* appName = "Weather_app";
//const char* hostname = "a.devices.dev.nabto.net";
const char* hostname = "localhost";

struct nc_attach_parameters attachParams;

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

uint8_t fp[] = {0xdd, 0x5f, 0xec, 0x4f, 0x27, 0xb5, 0x65, 0x7c, 0xb7, 0x5e, 0x5e, 0x24, 0x7f, 0xe7, 0x92, 0xcc};

struct test_context {
    int data;
};
struct np_platform pl;
struct nc_stream_manager_context streamManager;
struct nabto_stream* stream;
uint8_t buffer[1500];

void stream_application_event_callback(nabto_stream_application_event_type eventType, void* data)
{
    NABTO_LOG_ERROR(0, "application event callback eventType: %s", nabto_stream_application_event_type_to_string(eventType));
    if (eventType == NABTO_STREAM_APPLICATION_EVENT_TYPE_DATA_READY) {
        size_t readen = 0;
        size_t written = 0;
        nabto_stream_read_buffer(stream, buffer, 1500, &readen);
        if (readen > 0) {
            nabto_stream_write_buffer(stream, buffer, readen, &written);
            NABTO_LOG_ERROR(0, "application event wrote %u bytes", written);
        }
    }
}

void stream_listener(struct nabto_stream* incStream, void* data)
{
    NABTO_LOG_ERROR(0, "Test listener callback ");
    stream = incStream;
    nabto_stream_set_application_event_callback(stream, &stream_application_event_callback, data);
    nabto_stream_accept(stream);
}

void attachedCb(const np_error_code ec, void* data) {
    // NABTO_LOG_INFO(0, "dtlsS.create: %04x dtlsS.send: %04x dtlsS.get_fp: %04x dtlsS.recv: %04x dtlsS.cancel_recv: %04x dtlsS.close: %04x", (uint32_t*)pl.dtlsS.create, (uint32_t*)pl.dtlsS.async_send_to, (uint32_t*)pl.dtlsS.get_fingerprint, (uint32_t*)pl.dtlsS.async_recv_from, (uint32_t*)pl.dtlsS.cancel_recv_from, (uint32_t*)pl.dtlsS.async_close);
    if (ec == NABTO_EC_OK) {
        NABTO_LOG_INFO(0, "Received attached callback with NABTO_EC_OK");
    } else {
        NABTO_LOG_INFO(0, "Received attached callback with ERROR %u", ec);
        exit(1);
    }
}


int main() {
    struct nc_attach_context attach;
    np_platform_init(&pl);
    nm_unix_comm_buf_init(&pl);
    nm_epoll_init(&pl);
    nm_dtls_init(&pl, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));
    nm_dtls_srv_init(&pl, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));
    nm_unix_ts_init(&pl);
    nm_unix_dns_init(&pl);
  
    np_log.log = &nm_unix_log;
    np_log.log_buf = &nm_unix_log_buf;

    struct test_context data;
    data.data = 42;

    nc_stream_manager_init(&streamManager, &pl);
    nc_client_connect_dispatch_init(&pl, &streamManager);
    nc_stream_manager_set_listener(&streamManager, &stream_listener, &data);
    
    attachParams.appName = appName;
    attachParams.appNameLength = strlen(appName);
    attachParams.appVersion = appVer;
    attachParams.appVersionLength = strlen(appVer);
    attachParams.hostname = hostname;
    attachParams.hostnameLength = strlen(hostname);
    
    nc_attacher_async_attach(&attach, &pl, &attachParams, attachedCb, &data);

    while (true) {
        np_event_queue_execute_all(&pl);
        nm_epoll_wait();
    }

    exit(0);
}
