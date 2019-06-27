
#include "nm_access_control.h"
#include "nm_iam_parse.h"
#include <platform/np_unit_test.h>

const char* testPolicy1 = "{ \"version\": 1, \"name\": \"FirmwareUpdate\", \"statements\": [ { \"effect\": \"allow\", \"actions\": [ \"firmeware:update\", \"firmware:show\" ] } ] }";


void test_parse_policy()
{
    struct nm_iam iam;
    nm_iam_init(&iam);
    struct nm_iam_policy* policy = nm_iam_parse_policy(&iam, testPolicy1);
    NABTO_TEST_CHECK(policy != NULL);
    NABTO_TEST_CHECK(strcmp(policy->name, "FirmwareUpdate") == 0);
}


void nm_iam_parse_test()
{
    return test_parse_policy();
}
