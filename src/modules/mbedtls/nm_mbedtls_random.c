#include "nm_mbedtls_random.h"

#include <platform/np_error_code.h>
#include <platform/np_platform.h>
#include <platform/np_allocator.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>



static np_error_code make_random(struct np_platform* pl, void* buffer, size_t bufferSize);

struct random_ctx {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
};

static void free_random_ctx(struct random_ctx* ctx) {
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    np_free(ctx);
}

bool nm_mbedtls_random_init(struct np_platform* pl)
{
    struct random_ctx* ctx = np_calloc(1, sizeof(struct random_ctx));
    if (ctx == NULL) {
        return false;
    }
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);
    int ret;
    ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0);
    if (ret != 0) {
        free_random_ctx(ctx);
        return false;
    }
    pl->randomData = ctx;

    pl->random.random = &make_random;
    return true;
}

void nm_mbedtls_random_deinit(struct np_platform* pl)
{
    struct random_ctx* ctx = pl->randomData;
    if (ctx == NULL) {
        return;
    }
    free_random_ctx(ctx);
}

np_error_code make_random(struct np_platform* pl, void* buffer, size_t bufferSize)
{
    struct random_ctx* ctx = pl->randomData;
    int i = mbedtls_ctr_drbg_random(&ctx->ctr_drbg, buffer, bufferSize);
    if (i == 0) {
        return NABTO_EC_OK;
    }
    return NABTO_EC_UNKNOWN;
}
