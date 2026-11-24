#include "nm_openssl_spake2.h"
#include "nm_openssl_util.h"

#include <platform/np_spake2.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <string.h>

/**
 * Definitions of the curve points M and N, which is used in the
 * spake2 algorithm.
 */
static const uint8_t Mdata[] = {
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d,
    0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3,
    0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
    0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e,
    0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7,
    0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20};

static const uint8_t Ndata[] = {
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d,
    0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01,
    0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
    0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36,
    0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80,
    0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7};

struct spake2_ctx {
    BN_CTX* bnCtx;
    EC_GROUP* grp;
    EC_POINT* T;
    EC_POINT* S;
    EC_POINT* M;
    EC_POINT* N;
    EC_POINT* Y;
    EC_POINT* K;
    EC_POINT* tmpPoint;
    BIGNUM* y;
    BIGNUM* w;
    BIGNUM* tmp;
};

static np_error_code openssl_spake2_calculate_key(
    struct nc_spake2_password_request* req, const char* password,
    uint8_t* resp, size_t* respLen, uint8_t* spake2Key);
static np_error_code openssl_spake2_key_confirmation(
    uint8_t* payload, size_t payloadLen, uint8_t* key, size_t keyLen,
    uint8_t* hash1, size_t hash1Len);

np_error_code nm_openssl_spake2_init(struct np_platform* pl)
{
    pl->spake2.calculate_key = &openssl_spake2_calculate_key;
    pl->spake2.key_confirmation = &openssl_spake2_key_confirmation;
    return NABTO_EC_OK;
}

void nm_openssl_spake2_deinit(struct np_platform* pl)
{
    (void)pl;
}

static void spake2_ctx_free(struct spake2_ctx* ctx)
{
    EC_POINT_free(ctx->T);
    EC_POINT_free(ctx->S);
    EC_POINT_free(ctx->M);
    EC_POINT_free(ctx->N);
    EC_POINT_free(ctx->Y);
    EC_POINT_clear_free(ctx->K);
    EC_POINT_clear_free(ctx->tmpPoint);
    BN_clear_free(ctx->y);
    BN_clear_free(ctx->w);
    BN_clear_free(ctx->tmp);
    EC_GROUP_free(ctx->grp);
    BN_CTX_free(ctx->bnCtx);
}

static bool spake2_ctx_init(struct spake2_ctx* ctx)
{
    memset(ctx, 0, sizeof(struct spake2_ctx));
    ctx->bnCtx = BN_CTX_new();
    ctx->grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ctx->bnCtx == NULL || ctx->grp == NULL) {
        return false;
    }
    ctx->T = EC_POINT_new(ctx->grp);
    ctx->S = EC_POINT_new(ctx->grp);
    ctx->M = EC_POINT_new(ctx->grp);
    ctx->N = EC_POINT_new(ctx->grp);
    ctx->Y = EC_POINT_new(ctx->grp);
    ctx->K = EC_POINT_new(ctx->grp);
    ctx->tmpPoint = EC_POINT_new(ctx->grp);
    ctx->y = BN_secure_new();
    ctx->w = BN_secure_new();
    ctx->tmp = BN_secure_new();
    return ctx->T != NULL && ctx->S != NULL && ctx->M != NULL &&
           ctx->N != NULL && ctx->Y != NULL && ctx->K != NULL &&
           ctx->tmpPoint != NULL && ctx->y != NULL && ctx->w != NULL &&
           ctx->tmp != NULL;
}

static bool hash_length(EVP_MD_CTX* mdCtx, uint32_t val)
{
    uint8_t b[4];
    b[0] = (uint8_t)(val >> 24);
    b[1] = (uint8_t)(val >> 16);
    b[2] = (uint8_t)(val >> 8);
    b[3] = (uint8_t)val;
    return EVP_DigestUpdate(mdCtx, b, 4) == 1;
}

static bool hash_data(EVP_MD_CTX* mdCtx, const uint8_t* data, size_t dataLength)
{
    return hash_length(mdCtx, (uint32_t)dataLength) &&
           EVP_DigestUpdate(mdCtx, data, dataLength) == 1;
}

static bool hash_point(EVP_MD_CTX* mdCtx, struct spake2_ctx* ctx, const EC_POINT* p)
{
    uint8_t buffer[256];
    size_t olen = EC_POINT_point2oct(ctx->grp, p, POINT_CONVERSION_UNCOMPRESSED, buffer, sizeof(buffer), ctx->bnCtx);
    if (olen == 0) {
        return false;
    }
    return hash_data(mdCtx, buffer, olen);
}

static bool hash_bn(EVP_MD_CTX* mdCtx, const BIGNUM* n)
{
    // The minimal big endian encoding as mbedtls_mpi_write_binary with
    // mbedtls_mpi_size writes it.
    uint8_t buffer[256];
    int s = BN_num_bytes(n);
    if (s < 0 || s > (int)sizeof(buffer)) {
        return false;
    }
    if (BN_bn2bin(n, buffer) != s) {
        return false;
    }
    bool ok = hash_data(mdCtx, buffer, (size_t)s);
    OPENSSL_cleanse(buffer, sizeof(buffer));
    return ok;
}

// The calculation is split into steps which each return false on failure.
static bool calculate_points(struct spake2_ctx* ctx,
                             struct nc_spake2_password_request* req,
                             const uint8_t* y, size_t yLen,
                             const char* password)
{
    const BIGNUM* order = EC_GROUP_get0_order(ctx->grp);

    // T from the client, M and N are constants. oct2point fails if a point is
    // not on the curve.
    if (EC_POINT_oct2point(ctx->grp, ctx->T, req->T, req->Tlen, ctx->bnCtx) != 1 ||
        EC_POINT_oct2point(ctx->grp, ctx->M, Mdata, sizeof(Mdata), ctx->bnCtx) != 1 ||
        EC_POINT_oct2point(ctx->grp, ctx->N, Ndata, sizeof(Ndata), ctx->bnCtx) != 1) {
        return false;
    }

    // y is a random value in [1, n-1], Y = y*G
    if (y != NULL) {
        if (BN_bin2bn(y, (int)yLen, ctx->y) == NULL) {
            return false;
        }
    } else {
        do {
            if (BN_priv_rand_range_ex(ctx->y, order, 0, ctx->bnCtx) != 1) {
                return false;
            }
        } while (BN_is_zero(ctx->y));
    }
    if (BN_is_zero(ctx->y) || BN_cmp(ctx->y, order) >= 0) {
        return false;
    }
    BN_set_flags(ctx->y, BN_FLG_CONSTTIME);

    // Use a random password if a real one does not exist to mask an invalid
    // username.
    uint8_t passwordHash[32];
    if (password == NULL) {
        if (RAND_priv_bytes(passwordHash, sizeof(passwordHash)) != 1) {
            return false;
        }
    } else {
        if (nm_openssl_sha256((const uint8_t*)password, strlen(password), passwordHash) != 0) {
            return false;
        }
    }
    BIGNUM* w = BN_bin2bn(passwordHash, sizeof(passwordHash), ctx->w);
    OPENSSL_cleanse(passwordHash, sizeof(passwordHash));
    if (w == NULL) {
        return false;
    }
    BN_set_flags(ctx->w, BN_FLG_CONSTTIME);

    // Each multiplication has a single scalar, which OpenSSL calculates in
    // constant time. The sums are then made with point additions.

    // S = w*N + y*G
    if (EC_POINT_mul(ctx->grp, ctx->Y, ctx->y, NULL, NULL, ctx->bnCtx) != 1 ||
        EC_POINT_mul(ctx->grp, ctx->S, NULL, ctx->N, ctx->w, ctx->bnCtx) != 1 ||
        EC_POINT_add(ctx->grp, ctx->S, ctx->S, ctx->Y, ctx->bnCtx) != 1) {
        return false;
    }

    // K = y*(T-w*M) = y*T + ((-y*w mod n)*M)
    if (BN_mod_mul(ctx->tmp, ctx->y, ctx->w, order, ctx->bnCtx) != 1 ||
        BN_mod_sub(ctx->tmp, order, ctx->tmp, order, ctx->bnCtx) != 1) {
        return false;
    }
    BN_set_flags(ctx->tmp, BN_FLG_CONSTTIME);
    if (EC_POINT_mul(ctx->grp, ctx->K, NULL, ctx->T, ctx->y, ctx->bnCtx) != 1 ||
        EC_POINT_mul(ctx->grp, ctx->tmpPoint, NULL, ctx->M, ctx->tmp, ctx->bnCtx) != 1 ||
        EC_POINT_add(ctx->grp, ctx->K, ctx->K, ctx->tmpPoint, ctx->bnCtx) != 1) {
        return false;
    }
    return true;
}

static bool calculate_key_hash(struct spake2_ctx* ctx,
                               struct nc_spake2_password_request* req,
                               uint8_t* spake2Key)
{
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (mdCtx == NULL) {
        return false;
    }
    unsigned int keyLen = 0;
    // Key = H(encode(cliFp) || encode(devFp) || encode(T) || encode(S) ||
    // encode(K) || encode(w))
    bool ok = EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL) == 1 &&
              hash_data(mdCtx, req->clientFingerprint, 32) &&
              hash_data(mdCtx, req->deviceFingerprint, 32) &&
              hash_point(mdCtx, ctx, ctx->T) &&
              hash_point(mdCtx, ctx, ctx->S) &&
              hash_point(mdCtx, ctx, ctx->K) &&
              hash_bn(mdCtx, ctx->w) &&
              EVP_DigestFinal_ex(mdCtx, spake2Key, &keyLen) == 1 &&
              keyLen == 32;
    EVP_MD_CTX_free(mdCtx);
    return ok;
}

// T [in] from client
// CliFP [in] from client cert
// devFp [in] from dev cert
// pwd [in] from auth req
// S [out] returned to client
// Key [out] used in key_confirmation
np_error_code nm_openssl_spake2_calculate_key_with_y(
    struct nc_spake2_password_request* req, const uint8_t* y, size_t yLen,
    const char* password, uint8_t* resp, size_t* respLen, uint8_t* spake2Key)
{
    struct spake2_ctx ctx;
    np_error_code ec = NABTO_EC_FAILED;
    if (spake2_ctx_init(&ctx) &&
        calculate_points(&ctx, req, y, yLen, password) &&
        calculate_key_hash(&ctx, req, spake2Key)) {
        size_t olen = EC_POINT_point2oct(ctx.grp, ctx.S, POINT_CONVERSION_UNCOMPRESSED, resp, *respLen, ctx.bnCtx);
        if (olen > 0) {
            *respLen = olen;
            ec = NABTO_EC_OK;
        }
    }
    spake2_ctx_free(&ctx);
    return ec;
}

static np_error_code openssl_spake2_calculate_key(
    struct nc_spake2_password_request* req, const char* password,
    uint8_t* resp, size_t* respLen, uint8_t* spake2Key)
{
    return nm_openssl_spake2_calculate_key_with_y(req, NULL, 0, password, resp, respLen, spake2Key);
}

static np_error_code openssl_spake2_key_confirmation(uint8_t* payload, size_t payloadLen, uint8_t* key, size_t keyLen, uint8_t* hash1, size_t hash1Len)
{
    if (payloadLen != 32 || keyLen != 32 || hash1Len != 32) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    uint8_t hash2[32];
    if (nm_openssl_sha256(key, 32, hash1) != 0 ||
        nm_openssl_sha256(hash1, 32, hash2) != 0) {
        return NABTO_EC_FAILED;
    }
    if (CRYPTO_memcmp(payload, hash2, 32) != 0) {
        return NABTO_EC_ACCESS_DENIED;
    }
    return NABTO_EC_OK;
}
