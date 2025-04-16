#include "nm_wolfssl_random.h"

#include <platform/np_error_code.h>
#include <platform/np_platform.h>
#include <platform/np_allocator.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>


static np_error_code make_random(struct np_platform* pl, void* buffer, size_t bufferSize);

struct random_ctx {
    WC_RNG rng;
};

static void free_random_ctx(struct random_ctx* ctx) {
    wc_FreeRng(&ctx->rng);
    np_free(ctx);
}

bool nm_wolfssl_random_init(struct np_platform* pl)
{
    struct random_ctx* ctx = np_calloc(1, sizeof(struct random_ctx));
    if (ctx == NULL) {
        return false;
    }
    int ret = 0;
    ret = wc_InitRng(&ctx->rng);
    if (ret != 0) {
        free_random_ctx(ctx);
        return false;
    }
    pl->randomData = ctx;

    pl->random.random = &make_random;
    return true;
}

void nm_wolfssl_random_deinit(struct np_platform* pl)
{

    struct random_ctx* ctx = pl->randomData;
    free_random_ctx(ctx);
}

np_error_code make_random(struct np_platform* pl, void* buffer, size_t bufferSize)
{
    struct random_ctx* ctx = pl->randomData;
    int i = wc_RNG_GenerateBlock(&ctx->rng, buffer, bufferSize);
    if (i == 0) {
        return NABTO_EC_OK;
    }
    return NABTO_EC_UNKNOWN;
}
