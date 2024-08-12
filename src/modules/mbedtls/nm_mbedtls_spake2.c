#include "nm_mbedtls_spake2.h"
#include "nm_mbedtls_util.h"

#if !defined(DEVICE_MBEDTLS_2)
#include <mbedtls/build_info.h>
#endif
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#include <string.h>

/**
 * Definitions of the curve points M and N, which is used in the
 * spake2 algorithm.
 */
const uint8_t Mdata[] = {
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d,
    0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3,
    0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
    0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e,
    0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7,
    0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20};

static uint8_t Ndata[] = {
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d,
    0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01,
    0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
    0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36,
    0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80,
    0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7};

static int hashLength(mbedtls_md_context_t* mdCtx, uint32_t val);
static int hashData(mbedtls_md_context_t* mdCtx, uint8_t* data, size_t dataLength);
static int hashPoint(mbedtls_md_context_t* mdCtx, mbedtls_ecp_group* grp, mbedtls_ecp_point* p);
static int hashMpi(mbedtls_md_context_t* mdCtx, mbedtls_mpi* n);


static np_error_code mbedtls_spake2_create(struct np_platform* pl,
                                           struct np_spake2_context** spake);
static void mbedtls_spake2_destroy(struct np_spake2_context* spake);
static np_error_code mbedtls_spake2_calculate_key(
    struct np_spake2_context* spake, struct nc_spake2_password_request* req, const char* password,
    uint8_t* resp, size_t* respLen, uint8_t* spake2Key);
static np_error_code mbedtls_spake2_key_confirmation(
    struct np_spake2_context* spake, uint8_t* payload, size_t payloadLen,
    uint8_t* key, size_t keyLen, uint8_t* hash1, size_t hash1Len);

np_error_code nm_mbedtls_spake2_init(struct np_platform* pl)
{
    pl->spake2.create = &mbedtls_spake2_create;
    pl->spake2.destroy = &mbedtls_spake2_destroy;
    pl->spake2.calculate_key = &mbedtls_spake2_calculate_key;
    pl->spake2.key_confirmation = &mbedtls_spake2_key_confirmation;
    return NABTO_EC_OK;
}

void nm_mbedtls_spake2_deinit(struct np_platform* pl)
{

}

static np_error_code mbedtls_spake2_create(struct np_platform* pl, struct np_spake2_context** spake)
{
    return NABTO_EC_NOT_IMPLEMENTED;
}

static void mbedtls_spake2_destroy(struct np_spake2_context* spake)
{

}

// T [in] from client
// CliFP [in] from client cert
// devFp [in] from dev cert
// pwd [in] from auth req
// S [out] returned to client
// Key [out] used in key_confirmation
np_error_code nm_mbedtls_spake2_calculate_key(
    struct np_spake2_context* spake,
    struct nc_spake2_password_request* req,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng,
    const char* password,
    uint8_t* resp,
    size_t* respLen,
    uint8_t* spake2Key)
{
    mbedtls_ecp_point T;
    mbedtls_ecp_group tGrp;
    mbedtls_ecp_group_init(&tGrp);
    mbedtls_ecp_point_init(&T);

    mbedtls_ecp_point S;
    mbedtls_ecp_point_init(&S);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);


    // create T from binary
    int status = 0;
    status |= mbedtls_ecp_group_load(&tGrp, MBEDTLS_ECP_DP_SECP256R1);
    status |= mbedtls_ecp_point_read_binary(&tGrp, &T, req->T, req->Tlen);


    status |= mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    mbedtls_ecp_point M;
    mbedtls_ecp_point N;
    mbedtls_ecp_point Y;
    mbedtls_ecp_point K;

    mbedtls_mpi y;
    mbedtls_mpi w;

    mbedtls_ecp_point_init(&M);
    mbedtls_ecp_point_init(&N);
    mbedtls_ecp_point_init(&Y);
    mbedtls_ecp_point_init(&K);

    mbedtls_mpi_init(&y);
    mbedtls_mpi_init(&w);

    // create M and N from binary
    status |= mbedtls_ecp_point_read_binary(&grp, &M, Mdata, sizeof(Mdata));
    status |= mbedtls_ecp_point_read_binary(&grp, &N, Ndata, sizeof(Ndata));

    uint8_t passwordHash[32];

    {
        // Generate random value for y and create Y
        status |= mbedtls_ecp_gen_keypair( &grp, &y, &Y, f_rng, p_rng);

        // Use dummy pwd if a real one don't exist to mask invalid username
        if (password == NULL) {
            status |= f_rng(p_rng, passwordHash, 32);
        } else {
            status |= nm_mbedtls_sha256((const uint8_t*)password, strlen(password), passwordHash);
        }
        // create password hash from binary
        status |= mbedtls_mpi_read_binary(&w, passwordHash, sizeof(passwordHash));
    }

    {
        mbedtls_mpi tmp;
        mbedtls_mpi_init(&tmp);
        status |= mbedtls_mpi_lset(&tmp, 1);

        // S = N*w + Y*1
        status |= mbedtls_ecp_muladd(&grp, &S, &w, &N, &tmp, &Y);

        // K = 1*y*(T-w*M) = y*T - y*w*M

        // tmp = -w*y mod n
        status |= mbedtls_mpi_lset(&tmp, -1);
        status |= mbedtls_mpi_mul_mpi(&tmp, &tmp, &y);
        status |= mbedtls_mpi_mul_mpi(&tmp, &tmp, &w);
        status |= mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp.N);

        // K = y*T+((-y*w)*M) = y*T+(tmp*M)
        status |= mbedtls_ecp_muladd(&grp, &K, &y, &T, &tmp, &M);

        mbedtls_mpi_free(&tmp);
    }

    {
        mbedtls_md_context_t mdCtx;
        mbedtls_md_init(&mdCtx);
        status |= mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        status |= mbedtls_md_starts(&mdCtx);

        // TT = encode(cliFp) || encode(devFp) ||
        status |= hashData(&mdCtx, req->clientFingerprint, 32);
        status |= hashData(&mdCtx, req->deviceFingerprint, 32);

        // encode(T) || encode(S) || encode(K) ||
        status |= hashPoint(&mdCtx, &grp, &T);
        status |= hashPoint(&mdCtx, &grp, &S);
        status |= hashPoint(&mdCtx, &grp, &K);

        // encode(w)
        status |= hashMpi(&mdCtx, &w);

        // create Key = H(TT)
        status |= mbedtls_md_finish(&mdCtx, spake2Key);

        mbedtls_md_free(&mdCtx);
    }

    mbedtls_ecp_point_free(&M);
    mbedtls_ecp_point_free(&N);
    mbedtls_ecp_point_free(&Y);
    mbedtls_ecp_point_free(&K);

    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&w);
    status |= mbedtls_ecp_point_write_binary (&grp, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, respLen, resp, 256);

    mbedtls_ecp_point_free(&S);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&T);
    mbedtls_ecp_group_free(&tGrp);

    if (status == 0) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_FAILED;
    }
}

static np_error_code mbedtls_spake2_calculate_key(
    struct np_spake2_context* spake, struct nc_spake2_password_request* req, const char* password,
    uint8_t* resp, size_t* respLen, uint8_t* spake2Key)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    int status = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (status != 0) {
        return NABTO_EC_FAILED;
    }

    np_error_code ec =  nm_mbedtls_spake2_calculate_key(spake, req, mbedtls_ctr_drbg_random, &ctr_drbg, password, resp, respLen, spake2Key);

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ec;
}

static np_error_code mbedtls_spake2_key_confirmation(struct np_spake2_context* spake, uint8_t* payload, size_t payloadLen, uint8_t* key, size_t keyLen, uint8_t* hash1, size_t hash1Len)
{
    if(payloadLen != 32 || keyLen != 32 || hash1Len != 32) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    uint8_t hash2[32];
    nm_mbedtls_sha256(key, 32, hash1);
    nm_mbedtls_sha256(hash1, 32, hash2);
    if (memcmp(payload, hash2, 32) != 0) {
        return NABTO_EC_ACCESS_DENIED;
    } else {
        return NABTO_EC_OK;
    }
}


int hashLength(mbedtls_md_context_t* mdCtx, uint32_t val)
{
    uint8_t b[4];
    b[0] = (uint8_t)(val >> 24);
    b[1] = (uint8_t)(val >> 16);
    b[2] = (uint8_t)(val >> 8);
    b[3] = (uint8_t)val;

    return mbedtls_md_update(mdCtx, b, 4);
}

int hashData(mbedtls_md_context_t* mdCtx, uint8_t* data, size_t dataLength)
{
    int status = 0;
    status |= hashLength(mdCtx, (uint32_t)dataLength);
    status |= mbedtls_md_update(mdCtx, data, dataLength);
    return status;
}

int hashPoint(mbedtls_md_context_t* mdCtx, mbedtls_ecp_group* grp, mbedtls_ecp_point* p)
{
    size_t olen;
    uint8_t buffer[256];
    int status = 0;
    status |= mbedtls_ecp_point_write_binary (grp, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buffer, sizeof(buffer));
    status |= hashData(mdCtx, buffer, olen);
    return status;
}

int hashMpi(mbedtls_md_context_t* mdCtx, mbedtls_mpi* n)
{
    size_t s = mbedtls_mpi_size(n);
    uint8_t buffer[256];
    int status = 0;
    if (s > 256) {
        return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }
    status |= mbedtls_mpi_write_binary (n, buffer, s);
    status |= hashData(mdCtx, buffer, s);
    return status;
}
