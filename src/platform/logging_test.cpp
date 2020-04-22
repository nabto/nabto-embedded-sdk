#include <boost/test/unit_test.hpp>


namespace {
struct print {
    uint32_t severity;
    uint32_t module;
    uint32_t arg1;
    char arg2;
    char fmt [64];
};

struct print pnt;

void test_log (uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args)
{
    pnt.severity = severity;
    pnt.module = module;
    strncpy(pnt.fmt, fmt, 64);
    pnt.arg1 = va_arg(args, uint32_t);
    pnt.arg2 = (char)va_arg(args, uint32_t);
}

bool check_pnt(uint32_t s, uint32_t m, const char* fmt, uint32_t a1, char a2)
{
    if (s != pnt.severity) {
        return false;
    }
    if (m != pnt.module) {
        return false;
    }
    if (strcmp(fmt,pnt.fmt) != 0) {
        return false;
    }
    if (a1 != pnt.arg1) {
        return false;
    }
    if (a2 != pnt.arg2) {
        return false;
    }
    return true;
}

void reset_pnt()
{
    int i;
    pnt.severity = 0;
    pnt.module = 0;
    pnt.arg1 = 0;
    pnt.arg2 = 0;
    for (i = 0; i<64; i++) {
        pnt.fmt[i] = 0;
    }
}

} // namespace

BOOST_AUTO_TEST_SUITE()

BOOST_AUTO_TEST_CASE()
{
    reset_pnt();
    np_log.log=&test_log;
    NABTO_LOG_ERROR(43, "%d:%c", 20, 'e');
    BOOST_TEST(check_pnt(NABTO_LOG_SEVERITY_ERROR, 43, "%d:%c", 20 , 'e'));
    reset_pnt();
    NABTO_LOG_WARN (44, "%d:%c", 21, 'd');
    BOOS_TEST(check_pnt(NABTO_LOG_SEVERITY_WARN, 44, "%d:%c", 21 , 'd'));
    reset_pnt();
    NABTO_LOG_INFO (45, "%d:%c", 22, 'c');
    BOOST_TEST(check_pnt(NABTO_LOG_SEVERITY_INFO, 45, "%d:%c", 22 , 'c'));
    reset_pnt();
    NABTO_LOG_TRACE(47, "%d:%c", 24, 'a');
    BOOST_TEST(check_pnt(NABTO_LOG_SEVERITY_TRACE, 47, "%d:%c", 24 , 'a'));
    reset_pnt();
    NABTO_LOG_INFO(48, "test with no variadic arguments");
    BOOST_TEST(pnt.severity == NABTO_LOG_SEVERITY_INFO);
    BOOST_TEST(pnt.module == 48);
}

BOOST_AUTO_TEST_SUITE_END()
