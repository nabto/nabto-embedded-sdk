#include "nc_stream_manager.h"
#include "nc_stream.h"

#include <core/nc_client_connect.h>

#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <core/nc_tests.h>

struct nc_stream_test_context {
    struct nc_client_connection conn;
};

struct nc_stream_test_context ctx;


void nc_stream_test_syn_ack()
{
    NABTO_TEST_CHECK(true);
}


void nc_stream_tests()
{
    nc_stream_test_syn_ack();
}
