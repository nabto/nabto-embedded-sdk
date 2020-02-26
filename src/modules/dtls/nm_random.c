#include "nm_random.h"

static void make_random(struct np_platform* pl, void* buffer, size_t bufferSize);

struct random_ctx {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
};

static void free_random_ctx(struct random_ctx* ctx) {
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    free(ctx);
}

bool nm_random_init(struct np_platform* pl)
{
    struct random_ctx* ctx = calloc(1, sizeof(struct random_ctx));
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
    pl->randomCtx = ctx;

    pl->random.random = &make_random;
}

void nm_random_deinit(struct np_platform* pl)
{

    struct random_ctx* ctx = pl->randomCtx;
    free_random_ctx(ctx);
}

np_error_code make_random(struct np_platform* pl, void* buffer, size_t bufferSize)
{
    struct random_ctx* ctx = pl->randomCtx;
    int i = mbedtls_ctr_drbg_random(&ctx->ctr_drbg, buffer, bufferSize);
    if (i == 0) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_FAILED;
    }
}
