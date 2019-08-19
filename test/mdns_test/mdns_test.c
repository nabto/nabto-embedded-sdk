#include <modules/mdns/nm_mdns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_timestamp.h>
#include <test_platform/test_platform.h>

#include <stdio.h>

const char* productId = "pr-test";
const char* deviceId = "de-test";
const uint16_t port = 1234;

uint16_t getPort(void* userData)
{
    return 4242;
}

int main(int argc, char** argv)
{
    struct test_platform tp;
    struct nm_mdns mdns;

    struct np_platform* pl;

    test_platform_init(&tp);
    pl = &tp.pl;

    nm_mdns_init(&mdns, pl, productId, deviceId, getPort, NULL);

    test_platform_run(&tp);

    nm_mdns_deinit(&mdns);
}
