#include <platform/unit_test.h>
#include <platform/tests.h>

#include <stdio.h>
#include <stdlib.h>

struct nabto_test_system nts;

void on_check_fail(const char* file, int line)
{
    printf("check failed: %s:%i\n", file, line);
}

int main() {
    nts.on_check_fail = on_check_fail;
    nabto_platform_test_run_all();

    printf("%i errors, %i ok checks\n", nts.fail, nts.ok);
    if (nts.fail > 0) {
        exit(1);
    } else {
        exit(0);
    }
}
