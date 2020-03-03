#include <boost/test/unit_test.hpp>

#include <platform/np_list.h>

BOOST_AUTO_TEST_SUITE(list)

BOOST_AUTO_TEST_CASE(create_insert_remove)
{
    struct np_list list;
    np_list_init(&list);

    struct np_list_item item1;
    struct np_list_item item2;

    const char* foo = "foo";
    const char* bar = "bar";

    BOOST_TEST(np_list_empty(&list));
    np_list_append(&list, &item1, (void*)foo);
    np_list_append(&list, &item2, (void*)bar);

    struct np_list_iterator it;
    np_list_front(&list, &it);
    BOOST_TEST(!np_list_end(&it));
    BOOST_TEST(np_list_get_element(&it) == (void*)foo);
    np_list_next(&it);
    BOOST_TEST(np_list_get_element(&it) == (void*)bar);
    np_list_next(&it);
    BOOST_TEST(np_list_end(&it));

    np_list_front(&list, &it);
    np_list_erase_iterator(&it);
    np_list_front(&list, &it);
    np_list_erase_iterator(&it);
    BOOST_TEST(np_list_empty(&list));

    np_list_deinit(&list);
}

BOOST_AUTO_TEST_SUITE_END();
