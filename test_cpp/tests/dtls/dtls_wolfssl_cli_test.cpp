#include <nabto/nabto_device_config.h>
#if defined(NABTO_DEVICE_WOLFSSL)

#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#include <platform/np_platform.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <stdlib.h>
#include <string>

#if !defined(WOLFSSL_DEBUG_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY)

namespace {

/**
 * Fails the wolfSSL allocations of one given size while it exists.
 */
class FailingWolfsslAllocator {
 public:
    FailingWolfsslAllocator(size_t size)
    {
        wolfSSL_GetAllocators(&malloc_, &free_, &realloc_);
        failSize() = size;
        wolfSSL_SetAllocators(&FailingWolfsslAllocator::mallocImpl, free_, realloc_);
    }

    ~FailingWolfsslAllocator()
    {
        wolfSSL_SetAllocators(malloc_, free_, realloc_);
    }

 private:
    static void* mallocImpl(size_t size)
    {
        if (size == failSize()) {
            return NULL;
        }
        return malloc(size);
    }

    static size_t& failSize()
    {
        static size_t size = 0;
        return size;
    }

    wolfSSL_Malloc_cb malloc_ = NULL;
    wolfSSL_Free_cb free_ = NULL;
    wolfSSL_Realloc_cb realloc_ = NULL;
};

np_error_code sender(uint8_t channelId, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* cb, void* data)
{
    (void)channelId; (void)buffer; (void)bufferSize; (void)cb; (void)data;
    return NABTO_EC_FAILED;
}

void dataHandler(uint8_t channelId, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data)
{
    (void)channelId; (void)seq; (void)buffer; (void)bufferSize; (void)data;
}

void eventHandler(enum np_dtls_event event, void* data)
{
    (void)event; (void)data;
}

} // namespace

BOOST_AUTO_TEST_SUITE(dtls_wolfssl_cli)

BOOST_AUTO_TEST_CASE(create_attach_connection_sni_failure)
{
    auto tp = nabto::test::TestPlatform::create();
    struct np_platform* pl = tp->getPlatform();

    // The SNI hostname is copied into an allocation of its length + 1, which
    // no other allocation made while creating the connection has.
    std::string sni(1000, 'a');
    struct np_dtls_cli_connection* conn = NULL;
    np_error_code ec;
    {
        FailingWolfsslAllocator allocator(sni.size() + 1);
        ec = pl->dtlsC.create_attach_connection(pl, &conn, sni.c_str(), false, &sender, &dataHandler, &eventHandler, NULL);
    }
    BOOST_TEST(ec != NABTO_EC_OK);
    // The connection has been freed, the caller must not get a pointer to it.
    BOOST_TEST(conn == (struct np_dtls_cli_connection*)NULL);
    if (ec == NABTO_EC_OK) {
        pl->dtlsC.destroy_connection(conn);
    }
}

BOOST_AUTO_TEST_SUITE_END()

#endif
#endif
