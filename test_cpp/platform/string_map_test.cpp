#include <boost/test/unit_test.hpp>

#include <platform/np_string_map.h>

BOOST_AUTO_TEST_SUITE(string_map)

BOOST_AUTO_TEST_CASE(basic)
{
    struct np_string_map map;
    np_string_map_init(&map);

    BOOST_TEST(np_string_map_insert(&map, "key", "value") == NABTO_EC_OK);

    struct np_string_map_item* item = np_string_map_get(&map, "key");
    BOOST_TEST(item != (void*)NULL);

    item = np_string_map_get(&map, "nonexisting");
    BOOST_TEST(item == (void*)NULL);

    np_string_map_deinit(&map);
}

BOOST_AUTO_TEST_SUITE_END()
