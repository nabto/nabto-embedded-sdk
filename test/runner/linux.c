#include <platform/np_unit_test.h>
#include <platform/np_tests.h>
#include <modules/access_control/nm_access_control_tests.h>
#include <core/nc_tests.h>

#include <stdio.h>
#include <stdlib.h>

struct np_test_system nts;

void on_check_fail(const char* file, int line)
{
    printf("check failed: %s:%i\n", file, line);
}

int main() {
    nts.on_check_fail = on_check_fail;
    np_platform_test_run_all();
    nc_core_test_run_all();
    nm_access_control_test_run_all();

    printf("%i errors, %i ok checks\n", nts.fail, nts.ok);
    if (nts.fail > 0) {
        exit(1);
    } else {
        exit(0);
    }
}
