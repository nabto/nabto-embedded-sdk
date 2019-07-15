#include "nm_iam_tests.h"

#include "nm_iam_parse_test.h"



void nm_access_control_test_run_all() {
    nm_iam_test_create_programmatic_policy();
    nm_iam_parse_test();
}
