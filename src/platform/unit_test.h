#ifndef UNABTO_UNiT_TEST_H
#define UNABTO_UNiT_TEST_H

struct unabto_test_system {
    void (*on_check_fail)(const char* file, int line);
    int ok;
    int fail;
};

extern struct unabto_test_system uts;

#define UNABTO_TEST_CHECK(expr) do { if((expr)) { uts.ok++; } else { uts.on_check_fail(__FILE__,__LINE__); uts.fail++; } } while (0)

#endif
