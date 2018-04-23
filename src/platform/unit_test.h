#ifndef NABTO_UNiT_TEST_H
#define NABTO_UNiT_TEST_H

struct nabto_test_system {
    void (*on_check_fail)(const char* file, int line);
    int ok;
    int fail;
};

extern struct nabto_test_system nts;

#define NABTO_TEST_CHECK(expr) do { if((expr)) { nts.ok++; } else { nts.on_check_fail(__FILE__,__LINE__); nts.fail++; } } while (0)

#endif
