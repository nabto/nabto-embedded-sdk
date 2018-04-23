#include <platform/unit_test.h>
#include <platform/ip_address_test.h>
#include <platform/nabto_logging_test.h>

#include <stdio.h>
#include <stdlib.h>

struct nabto_test_system nts;

void on_check_fail(const char* file, int line)
{
    printf("check failed: %s:%i\n", file, line);
}

int main() {
    nts.on_check_fail = on_check_fail;
    nabto_ip_address_test_is_v4();
    nabto_ip_address_test_is_v6();
    nabto_logging_test();

    printf("%i errors, %i ok checks\n", nts.fail, nts.ok);
    if (nts.fail > 0) {
        exit(1);
    } else {
        exit(0);
    }
}
