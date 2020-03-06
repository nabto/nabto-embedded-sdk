#include <boost/test/unit_test.hpp>

#include <platform/np_vector.h>

BOOST_AUTO_TEST_SUITE(vector)

void free_string(void* ptr)
{
    free(ptr);
}

BOOST_AUTO_TEST_CASE(init)
{
    struct np_vector vector;
    BOOST_TEST(np_vector_init(&vector, free_string) == NABTO_EC_OK);

    char* foo = strdup("foo");

    BOOST_TEST(np_vector_size(&vector) == (size_t)0);
    BOOST_TEST(np_vector_empty(&vector));
    BOOST_TEST(np_vector_push_back(&vector, foo) == NABTO_EC_OK);
    BOOST_TEST(np_vector_size(&vector) == (size_t)1);
    BOOST_TEST(!np_vector_empty(&vector));

    BOOST_TEST(np_vector_get(&vector, 0) == foo);

    np_vector_deinit(&vector);
    // check with valgrind that no memory is leaked.
}

BOOST_AUTO_TEST_CASE(erase)
{
    struct np_vector vector;
    BOOST_TEST(np_vector_init(&vector, free_string) == NABTO_EC_OK);

    char* foo = strdup("foo");
    char* bar = strdup("bar");
    char* baz = strdup("baz");

    BOOST_TEST(np_vector_push_back(&vector, foo) == NABTO_EC_OK);
    BOOST_TEST(np_vector_push_back(&vector, bar) == NABTO_EC_OK);
    BOOST_TEST(np_vector_push_back(&vector, baz) == NABTO_EC_OK);

    BOOST_TEST(np_vector_size(&vector) == (size_t)3);

    np_vector_erase(&vector, 2);

    BOOST_TEST(np_vector_size(&vector) == (size_t)2);

    np_vector_erase(&vector, 0);
    np_vector_erase(&vector, 0);

    BOOST_TEST(np_vector_size(&vector) == (size_t)0);

    np_vector_deinit(&vector);
    // check with valgrind that no memory is leaked.
}


BOOST_AUTO_TEST_SUITE_END()
