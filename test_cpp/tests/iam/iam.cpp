#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <modules/iam/nm_iam.h>
#include <nn/string_set.h>

#include <platform/np_allocator.h>

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(set_notification_categories, *boost::unit_test::timeout(180))
{
    NabtoDevice* d = nabto_device_new();
    const char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        nabto_device_set_log_level(d, logLevel);
        nabto_device_set_log_std_out_callback(d);
    }
    struct nm_iam iam;
    nm_iam_init(&iam, d, NULL);
    struct nn_string_set cats;
    nn_string_set_init(&cats, np_allocator_get());
    nn_string_set_insert(&cats, "cat1");
    nn_string_set_insert(&cats, "cat2");
    BOOST_TEST(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    BOOST_TEST(nn_string_set_contains(&iam.notificationCategories, "cat1"));
    BOOST_TEST(nn_string_set_contains(&iam.notificationCategories, "cat2"));

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_SUITE_END()
