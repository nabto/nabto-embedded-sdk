#include <boost/test/unit_test.hpp>

#include <platform/np_util.h>

BOOST_AUTO_TEST_SUITE(hex)

BOOST_AUTO_TEST_CASE(encode)
{
    uint8_t data[5] = { 0x42, 0x43, 0x44, 0x45, 0x4b };
    char output[11];
    memset(output, 0, 11);
    np_data_to_hex(data, 5, output);
    BOOST_TEST(std::string(output) == "424344454b");
}

BOOST_AUTO_TEST_CASE(decode)
{
    std::string hex = "424344454b";
    std::vector<uint8_t> out(5);
    std::vector<uint8_t> target = { 0x42, 0x43, 0x44, 0x45, 0x4b };
    np_hex_to_data(hex.c_str(), out.data(), out.size());
    BOOST_TEST(out == target);
}

BOOST_AUTO_TEST_CASE(decode_implicit_leading_zeroes)
{
    std::string hex = "24344454b";
    std::vector<uint8_t> out(5);
    std::vector<uint8_t> target = { 0x2, 0x43, 0x44, 0x45, 0x4b };
    np_hex_to_data(hex.c_str(), out.data(), out.size());
    BOOST_TEST(out == target);
}

BOOST_AUTO_TEST_CASE(decode_too_small_buffer)
{
    std::string hex = "4242";
    std::vector<uint8_t> out(1);
    BOOST_TEST(np_hex_to_data(hex.c_str(), out.data(), out.size()) == false);
}

BOOST_AUTO_TEST_SUITE_END()
