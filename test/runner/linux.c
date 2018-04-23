#include <platform/unit_test.h>
#include <platform/ip_address_test.h>

#include <stdio.h>

struct unabto_test_system uts;

void on_check_fail(const char* file, int line)
{
    printf("check failed: %s:%i\n", file, line);
}

int main() {
    uts.on_check_fail = on_check_fail;
    unabto_ip_address_test_is_v4();
    unabto_ip_address_test_is_v6();

    printf("%i errors, %i ok checks\n", uts.fail, uts.ok);
}
