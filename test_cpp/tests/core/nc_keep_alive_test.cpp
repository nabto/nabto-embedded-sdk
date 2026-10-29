#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#include <core/nc_keep_alive.h>

namespace {

void nop(void* data) { (void)data; }

} // namespace

BOOST_AUTO_TEST_SUITE(keep_alive)

BOOST_AUTO_TEST_CASE(valid_settings_are_applied)
{
    auto tp = nabto::test::TestPlatform::create();
    struct nc_keep_alive_context ctx;
    BOOST_TEST(nc_keep_alive_init(&ctx, tp->getPlatform(), &nop, NULL) == NABTO_EC_OK);

    BOOST_TEST(nc_keep_alive_set_settings(&ctx, 30000, 2000, 15));
    BOOST_TEST(ctx.kaInterval == 30000u);
    BOOST_TEST(ctx.kaRetryInterval == 2000u);
    BOOST_TEST(ctx.kaMaxRetries == 15u);
    BOOST_TEST(ctx.n == 15u);

    // The settings the attach tests use to detach quickly.
    BOOST_TEST(nc_keep_alive_set_settings(&ctx, 100, 50, 2));
    BOOST_TEST(ctx.kaRetryInterval == 50u);

    nc_keep_alive_deinit(&ctx);
}

BOOST_AUTO_TEST_CASE(out_of_range_settings_are_rejected)
{
    auto tp = nabto::test::TestPlatform::create();
    struct nc_keep_alive_context ctx;
    BOOST_TEST(nc_keep_alive_init(&ctx, tp->getPlatform(), &nop, NULL) == NABTO_EC_OK);

    // A zero retry interval is a division by zero, a multiple of 2^32 was a
    // zero retry interval after truncation to 32 bit.
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, 30000, 0, 15));
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, 30000, (uint64_t)1 << 32, 15));
    // A small retry interval makes the keep alive timer spin.
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, 30000, 1, 15));
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, 30000, NC_KEEP_ALIVE_MIN_RETRY_INTERVAL - 1, 15));
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, 1000, 2000, 15));
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, (uint64_t)1 << 32, 2000, 15));
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, 30000, 2000, (uint64_t)1 << 32));
    BOOST_TEST(!nc_keep_alive_set_settings(&ctx, 30000, 2000, UINT64_MAX));

    // The defaults are kept.
    BOOST_TEST(ctx.kaInterval == (uint32_t)NC_KEEP_ALIVE_DEFAULT_INTERVAL);
    BOOST_TEST(ctx.kaRetryInterval == (uint32_t)NC_KEEP_ALIVE_DEFAULT_RETRY_INTERVAL);
    BOOST_TEST(ctx.kaMaxRetries == (uint32_t)NC_KEEP_ALIVE_DEFAULT_MAX_RETRIES);

    nc_keep_alive_deinit(&ctx);
}

BOOST_AUTO_TEST_SUITE_END()
