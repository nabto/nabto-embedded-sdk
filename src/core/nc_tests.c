#include "nc_tests.h"

void nc_core_test_run_all()
{
    nc_attacher_tests();
    nc_connection_tests();
    nc_packet_tests();
}
