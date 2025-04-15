#include "random_string.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

// ambigious characters: "B8G6I1l0OQDS5Z2";

// generated by bash $ printf "%s" {a..z} {A..Z} {0..9} | tr -d "B8G6I1l0OQDS5Z2"
const char* alphabet = "abcdefghijkmnopqrstuvwxyzACEFHJKLMNPRTUVWXY3479";

struct random_ctx {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
};

static bool init_random(struct random_ctx* ctx);
static void deinit_random(struct random_ctx* ctx);

char* random_password(size_t outputSize)
{
    struct random_ctx ctx;
    if(!init_random(&ctx)) {
        deinit_random(&ctx);
        return NULL;
    }

    char* out = calloc(1, outputSize + 1);
    if (out == NULL) {
        deinit_random(&ctx);
        return NULL;
    }

    size_t alphabetSize = strlen(alphabet);

    size_t generated = 0;
    while (generated < outputSize) {
        uint8_t buffer = 0;
        int i = mbedtls_ctr_drbg_random(&ctx.ctr_drbg, &buffer, 1);
        if (i != 0) {
            free(out);
            deinit_random(&ctx);
            return NULL;
        }

        if (buffer < alphabetSize) {
            out[generated] = alphabet[buffer];
            generated++;
        }
    }

    deinit_random(&ctx);
    return out;
}


bool init_random(struct random_ctx* ctx)
{
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);

    int ret = 0;
    ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0);
    if (ret != 0) {
        return false;
    }
    return true;

}

void deinit_random(struct random_ctx* ctx)
{
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
}
