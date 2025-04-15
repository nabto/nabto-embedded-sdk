#include "nm_wolfssl_spake2.h"
#include "nm_wolfssl_util.h"

#include <platform/np_allocator.h>
#include <platform/np_spake2.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/integer.h>

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

static int hashData(wc_Sha256* mdCtx, uint8_t* data, size_t dataLength);
static int hashPoint(wc_Sha256* mdCtx, const int grp, ecc_point* p);
static int hashMpi(wc_Sha256* mdCtx, mp_int* n);

static np_error_code wolfssl_spake2_calculate_key(
    struct nc_spake2_password_request* req, const char* password,
    uint8_t* resp, size_t* respLen, uint8_t* spake2Key);

static np_error_code wolfssl_spake2_key_confirmation(
    uint8_t* payload, size_t payloadLen,
    uint8_t* key, size_t keyLen, uint8_t* hash1, size_t hash1Len);

static int calculate_S(mp_int* groupA, mp_int* modulus, ecc_point* N, mp_int* w, ecc_point* Y, ecc_point* S);
static int calculate_K(mp_int* groupA, mp_int* groupOrder, mp_int* modulus, mp_int* y, ecc_point* T, mp_int* w, ecc_point* M, ecc_point* K);

np_error_code nm_wolfssl_spake2_init(struct np_platform* pl)
{
    pl->spake2.calculate_key = &wolfssl_spake2_calculate_key;
    pl->spake2.key_confirmation = &wolfssl_spake2_key_confirmation;
    return NABTO_EC_OK;
}

void nm_wolfssl_spake2_deinit(struct np_platform* pl)
{

}

static int password_to_mpi_2(const char* password, mp_int* w, WC_RNG* rng, wc_Sha256* sha)
{
    int ret = 0;
    uint8_t hash[32];
    if (password == NULL) {
        ret = wc_RNG_GenerateBlock(rng, hash, sizeof(hash));
        if (ret != sizeof(hash)) {
            return ret;
        }
    } else {
        ret = wc_Sha256Update(sha, (const unsigned char*)password, (int)strlen(password));
        if (ret < 0) {
            return ret;
        }
        ret = wc_Sha256Final(sha, hash);
        if (ret < 0) {
            return ret;
        }
    }
    ret = mp_read_unsigned_bin(w, hash, sizeof(hash));
    return ret;
}

static int password_to_mpi(const char* password, mp_int* w, WC_RNG* rng)
{
    int ret = 0;
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    ret = password_to_mpi_2(password, w, rng, &sha);
    wc_Sha256Free(&sha);
    return ret;
}

// T [in] from client
// CliFP [in] from client cert
// devFp [in] from dev cert
// pwd [in] from auth req
// S [out] returned to client
// Key [out] used in key_confirmation

static int wolfssl_spake2_calculate_key_ex(
    struct nc_spake2_password_request* req,
    const char* password, uint8_t* resp, size_t* respLen, uint8_t* spake2Key,
    ecc_point* T, ecc_point* M, ecc_point* N, ecc_point* K, ecc_point* S,
    WC_RNG* rng, ecc_key* Y,
    mp_int* w, mp_int* groupA, mp_int* groupOrder, mp_int* groupPrime,
    wc_Sha256* sha)
{
    int ret = 0;
    ret = wc_ecc_make_key_ex(rng, 32, Y, ECC_SECP256R1);
    if (ret < 0) {
        return ret;
    }
    // ret = wc_ecc_make_pub(Y, NULL);
    // if (ret < 0) {
    //     return NABTO_EC_FAILED;
    // }
    int curveIdx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    if (curveIdx < 0) {
        return curveIdx;
    }
    const ecc_set_type* curveParams = wc_ecc_get_curve_params(curveIdx);

    // read T from a buffer. The point is encoded as 0x04 and the X, y
    // coordinate. 0x04 means the point is uncompressed.
    ret = wc_ecc_import_point_der(req->T, req->Tlen, curveIdx, T);
    if (ret < 0) {
        return ret;
    }

    ret = wc_ecc_import_point_der(Mdata, sizeof(Mdata), curveIdx, M);
    if (ret < 0) {
        return ret;
    }

    ret = wc_ecc_import_point_der(Ndata, sizeof(Ndata), curveIdx, N);
    if (ret < 0) {
        return ret;
    }


    ret = password_to_mpi(password, w, rng);
    if (ret < 0) {
        return ret;
    }


    ret = mp_read_radix(groupA, curveParams->Af, MP_RADIX_HEX);
    if (ret < 0) {
        return ret;
    }
    ret = mp_read_radix(groupPrime, curveParams->prime, MP_RADIX_HEX);
    if (ret < 0) {
        return ret;
    }
    ret = mp_read_radix(groupOrder, curveParams->order, MP_RADIX_HEX);
    if (ret < 0) {
        return ret;
    }

    // S = N*w + Y*1
    ret = calculate_S(groupA, groupPrime, N, w, &Y->pubkey, S);
    if (ret < 0) {
        return ret;
    }

    // K = 1*y*(T-w*M) = y*T - y*w*M
    ret = calculate_K(groupA, groupOrder, groupPrime, &Y->k, T, w, M, K);
    if (ret != 0) {
        return ret;
    }

    // TT = encode(cliFp) || encode(devFp) ||
    // encode(T) || encode(S) || encode(K) ||
    ret = hashData(sha, req->clientFingerprint, 32);
    if (ret != 0) {
        return ret;
    }
    ret = hashData(sha, req->deviceFingerprint, 32);
    if (ret != 0) {
        return ret;
    }
    ret = hashPoint(sha, curveIdx, T);
    if (ret != 0) {
        return ret;
    }
    ret = hashPoint(sha, curveIdx, S);
    if (ret != 0) {
        return ret;
    }
    ret = hashPoint(sha, curveIdx, K);
    if (ret != 0) {
        return ret;
    }

    // encode(w)
    ret = hashMpi(sha, w);
    if (ret != 0) {
        return ret;
    }

    // create Key = H(TT)
    ret = wc_Sha256Final(sha, spake2Key);
    if (ret != 0) {
        return ret;
    }

    word32 len = *respLen;

    ret = wc_ecc_export_point_der(curveIdx, S, resp, &len);
    if (ret != 0) {
        return ret;
    }
    *respLen = len;

    return 0;
}

static int calculate_key_allocate(struct nc_spake2_password_request* req,
    const char* password, uint8_t* resp, size_t* respLen, uint8_t* spake2Key)
{
    int ret = 0;
    ecc_point* T = NULL;
    ecc_point* M = NULL;
    ecc_point* N = NULL;
    ecc_point* K = NULL;
    ecc_point* S = NULL;
    T = wc_ecc_new_point();
    M = wc_ecc_new_point();
    N = wc_ecc_new_point();
    K = wc_ecc_new_point();
    S = wc_ecc_new_point();

    WC_RNG rng;
    ecc_key Y;

    mp_int w;
    mp_int groupA;
    mp_int groupOrder;
    mp_int groupPrime;

    wc_Sha256 sha;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        ret = wc_ecc_init(&Y);
        if (ret == 0) {

            ret = mp_init(&w);
            if (ret == 0) {
                ret = mp_init(&groupA);
                if (ret == 0) {
                    ret = mp_init(&groupOrder);
                    if (ret == 0) {
                        ret = mp_init(&groupPrime);
                        if (ret == 0) {

                            ret = wc_InitSha256(&sha);
                            if (ret == 0) {
                                ret = wolfssl_spake2_calculate_key_ex(
                                    req, password, resp, respLen,
                                    spake2Key, T, M, N, K, S, &rng, &Y,
                                    &w, &groupA, &groupOrder, &groupPrime,
                                    &sha);

                                wc_Sha256Free(&sha);
                            }
                            mp_free(&groupPrime);
                        }
                        mp_free(&groupOrder);
                    }
                    mp_free(&groupA);
                }
                mp_free(&w);
            }

            wc_ecc_free(&Y);
        }
        wc_FreeRng(&rng);
    }

    wc_ecc_del_point(S);
    wc_ecc_del_point(K);
    wc_ecc_del_point(N);
    wc_ecc_del_point(M);
    wc_ecc_del_point(T);
    return ret;
}

static np_error_code wolfssl_spake2_calculate_key(
    struct nc_spake2_password_request* req,
    const char* password, uint8_t* resp, size_t* respLen, uint8_t* spake2Key)
{
    int ret = calculate_key_allocate(req, password, resp, respLen, spake2Key);

    if (ret != 0) {
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

int calculate_S_ex(mp_int* groupA, mp_int* modulus, ecc_point* N, mp_int* w, ecc_point* Y, ecc_point* S, mp_int* one)
{
    int ret = 0;
    ret = mp_set(one, 1);
    if (ret != 0) {
        return ret;
    }

    return ecc_mul2add(N, w, Y, one, S, groupA, modulus, NULL);
}


int calculate_S(mp_int* groupA, mp_int* modulus, ecc_point* N, mp_int* w, ecc_point* Y, ecc_point* S)
{
    //S = N*w + Y*1
    int ret = 0;
    mp_int one;
    ret = mp_init(&one);
    if (ret != 0) {
        return ret;
    }
    ret = calculate_S_ex(groupA, modulus, N, w, Y, S, &one);
    mp_free(&one);
    return ret;
}

int calculate_K_ex(mp_int* groupA, mp_int* groupOrder, mp_int* groupPrime, mp_int* y, ecc_point* T, mp_int* w, ecc_point* M, ecc_point* K,
mp_int* zero, mp_int* one, mp_int* minusOne, mp_int* tmp)
{
    int ret = 0;
    ret = mp_set(zero, 0);
    if (ret != 0) {
        return ret;
    }
    ret = mp_set(one, 1);
    if (ret != 0) {
        return ret;
    }

    // -1 = 0 - 1 = groupOrder - 1
    ret = mp_submod(zero, one, groupOrder, minusOne);
    if (ret != 0) {
        return ret;
    }

    ret = mp_mulmod(minusOne, w, groupOrder, tmp);
    //ret = mp_mul(&minusOne, w, &tmp);
    if (ret != 0) {
        return ret;
    }

    ret = mp_mulmod(tmp, y, groupOrder, tmp);
    //ret = mp_mul(&tmp, y, &tmp);
    if (ret != 0) {
        return ret;
    }

    return ecc_mul2add(T, y, M, tmp, K, groupA, groupPrime, NULL);
}

int calculate_K(mp_int* groupA, mp_int* groupOrder, mp_int* groupPrime, mp_int* y, ecc_point* T, mp_int* w, ecc_point* M, ecc_point* K)
{
    // K = 1*y*(T-w*M) = y*T - y*w*M
    // tmp = -w*y mod n
    // K = y*T+((-y*w)*M) = y*T+(tmp*M)

    int ret = 0;
    mp_int zero;
    mp_int one;
    mp_int minusOne;
    mp_int tmp;
    ret = mp_init(&zero);
    if (ret == 0) {
        ret = mp_init(&one);
        if (ret == 0) {
            ret = mp_init(&minusOne);
            if (ret == 0) {
                ret = mp_init(&tmp);
                if (ret == 0) {
                    ret = calculate_K_ex(groupA, groupOrder, groupPrime, y, T, w, M, K, &zero, &one, &minusOne, &tmp);
                    mp_free(&tmp);
                }
                mp_free(&minusOne);
            }
            mp_free(&one);
        }
        mp_free(&zero);
    }

    return ret;
}

static int sha256_hash_ex(uint8_t* buffer, size_t bufferSize, uint8_t* hash, wc_Sha256* sha)
{
    int ret = 0;

    ret = wc_Sha256Update(sha, buffer, bufferSize);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Sha256Final(sha, hash);
    if (ret != 0) {
        return ret;
    }
    return 0;
}

static int sha256_hash(uint8_t* buffer, size_t bufferSize, uint8_t* hash)
{
    int ret = 0;
    wc_Sha256 sha;
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        return ret;
    }
    ret = sha256_hash_ex(buffer, bufferSize, hash, &sha);

    wc_Sha256Free(&sha);
    return ret;
}

static np_error_code wolfssl_spake2_key_confirmation(
    uint8_t* payload, size_t payloadLen,
    uint8_t* key, size_t keyLen, uint8_t* hash1, size_t hash1Len)
{
    if (payloadLen != 32 || keyLen != 32 || hash1Len != 32) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    uint8_t hash2[32];
    int ret = 0;
    ret = sha256_hash(key, keyLen, hash1);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }
    ret = sha256_hash(hash1, 32, hash2);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    if (memcmp(payload, hash2, 32) != 0) {
        return NABTO_EC_ACCESS_DENIED;
    } else {
        return NABTO_EC_OK;
    }
}

int hashLength(wc_Sha256* mdCtx, uint32_t val)
{
    uint8_t b[4];
    b[0] = (uint8_t)(val >> 24);
    b[1] = (uint8_t)(val >> 16);
    b[2] = (uint8_t)(val >> 8);
    b[3] = (uint8_t)val;

    return wc_Sha256Update(mdCtx, b, 4);
}

int hashData(wc_Sha256* mdCtx, uint8_t* data, size_t dataLength)
{
    int status = 0;
    status = hashLength(mdCtx, (uint32_t)dataLength);
    if (status < 0) {
        return status;
    }
    status = wc_Sha256Update(mdCtx, data, dataLength);
    return status;
}

int hashPoint(wc_Sha256* mdCtx, const int curveIdx, ecc_point* p)
{
    uint8_t buffer[256];
    int ret = 0;
    word32 outlen = sizeof(buffer);
    ret = wc_ecc_export_point_der(curveIdx, p, buffer, &outlen);
    if (ret < 0) {
        return ret;
    }
    ret = hashData(mdCtx, buffer, outlen);
    return ret;
}

int hashMpi(wc_Sha256* mdCtx, mp_int* n)
{
    size_t s = mp_unsigned_bin_size(n);
    uint8_t buffer[256];
    int ret = 0;
    if (s > 256) {
        return -1;  // TODO
    }
    ret = mp_to_unsigned_bin(n, buffer);
    if (ret < 0) {
        return ret;
    }
    ret = hashData(mdCtx, buffer, s);
    return ret;
}


/*******************************
 * Test code below.
 *******************************/

bool nm_wolfssl_spake2_test_hash_mpi()
{
    uint8_t buffer[5] = { 0x00, 0x00, 0x00, 0x01, 0x42 };

    uint8_t correctHash[32];
    uint8_t hash[32];

    mp_int n;
    mp_init(&n);
    mp_set(&n, 0x42);

    sha256_hash(buffer, sizeof(buffer), correctHash);
    {
        wc_Sha256 sha;
        wc_InitSha256(&sha);
        hashMpi(&sha, &n);
        wc_Sha256Final(&sha, hash);
    }

    return (memcmp(correctHash, hash, 32) == 0);
}

bool test_calculate_S()
{
    const uint8_t inputY[] = {0x04, 0x9d, 0xcd, 0x06, 0x86, 0xd5, 0x44, 0x8c, 0x28, 0x30, 0x9d, 0x52, 0xc4, 0xca, 0x2d, 0xc5, 0xc9, 0x66, 0x42, 0xec, 0x28, 0xae, 0x32, 0x6f, 0x41, 0xd8, 0xd5, 0x96, 0xfc, 0x64, 0x37, 0x38, 0x8a, 0x04, 0x6d, 0x4f, 0x29, 0xe6, 0x21, 0xe9, 0x56, 0x72, 0xc2, 0x4b, 0x46, 0xef, 0x81, 0x42, 0x96, 0xb1, 0x0e, 0xe3, 0x38, 0xa0, 0xa9, 0x94, 0x09, 0x06, 0x87, 0xa5, 0x01, 0x88, 0x91, 0x88, 0xe1,  };
    const uint8_t inputw[] = {0x2f, 0x75, 0x32, 0x7c, 0xcb, 0x81, 0xd0, 0x34, 0x0b, 0x8c, 0xe0, 0xc3, 0x13, 0xcb, 0xa2, 0xcd, 0x85, 0x75, 0x10, 0x38, 0x98, 0x60, 0x5a, 0xc4, 0xd8, 0x3d, 0xc5, 0x8c, 0xfe, 0x66, 0x1e, 0xf6 };
    const uint8_t expectedS[] = {0x04, 0xfe, 0xf2, 0x92, 0x32, 0xdb, 0x7b, 0xe1, 0xdb, 0xb5, 0x67, 0x51, 0x14, 0xad, 0x84, 0x79, 0x3a, 0x0c, 0x88, 0x9d, 0xcf, 0x88, 0x96, 0x0a, 0xe7, 0xcc, 0x28, 0xca, 0x73, 0xbb, 0x59, 0xac, 0xcd, 0x9d, 0x5f, 0x4d, 0x95, 0xd3, 0x40, 0xf7, 0x65, 0x0e, 0x86, 0x5d, 0x01, 0xe9, 0xd5, 0xf4, 0xdb, 0x7c, 0x1d, 0x60, 0x67, 0xc0, 0x47, 0x3e, 0x63, 0xa0, 0xb1, 0x14, 0x6c, 0xb5, 0x32, 0x7f, 0xab,  };

    int ret = 0;
    int curveIdx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* curveParams = wc_ecc_get_curve_params(curveIdx);
    mp_int groupA;
    mp_int groupPrime;
    ret = mp_init(&groupA);
    ret = mp_init(&groupPrime);
    ret = mp_read_radix(&groupA, curveParams->Af, MP_RADIX_HEX);
    ret = mp_read_radix(&groupPrime, curveParams->prime, MP_RADIX_HEX);

    ecc_point* N = wc_ecc_new_point();
    mp_int w;
    mp_init(&w);
    ecc_point* Y = wc_ecc_new_point();
    ecc_point* S = wc_ecc_new_point();

    ret = wc_ecc_import_point_der(Ndata, sizeof(Ndata), curveIdx, N);
    if (ret < 0) {
        return false;
    }

    ret = wc_ecc_import_point_der(inputY, sizeof(inputY), curveIdx, Y);

    mp_read_unsigned_bin(&w, inputw, sizeof(inputw));



    ret = calculate_S(&groupA, &groupPrime, N, &w, Y, S);

    uint8_t buffer[128];
    word32 outLen = sizeof(buffer);
    wc_ecc_export_point_der(curveIdx, S, buffer, &outLen);

    if (memcmp(buffer, expectedS, 65) != 0) {
        return false;
    }

    mp_free(&groupA);
    mp_free(&groupPrime);
    mp_free(&w);
    wc_ecc_del_point(N);
    wc_ecc_del_point(Y);
    wc_ecc_del_point(S);

    return true;
}

bool test_calculate_K()
{
    uint8_t inputT[] = {0x04, 0x1f, 0x72, 0xa1, 0xbc, 0x78, 0xcf, 0xe5, 0x99, 0xbb, 0xce, 0x67, 0x1d, 0xcf, 0xd4, 0x3f, 0xb2, 0x1a, 0x94, 0x3c, 0x00, 0x61, 0x57, 0x11, 0xf7, 0x7c, 0x66, 0x0f, 0xe2, 0xac, 0x2f, 0xcc, 0x7b, 0xa8, 0xcc, 0x76, 0xa5, 0x80, 0x38, 0x1e, 0xe3, 0x34, 0x22, 0xb3, 0x87, 0x7b, 0xc1, 0x16, 0x32, 0xe5, 0x81, 0x7a, 0x9f, 0xf8, 0xd9, 0xdb, 0x22, 0x46, 0x9a, 0x93, 0x19, 0xdd, 0x63, 0x3a, 0x82,  };
    uint8_t inputw[] = {0x2f, 0x75, 0x32, 0x7c, 0xcb, 0x81, 0xd0, 0x34, 0x0b, 0x8c, 0xe0, 0xc3, 0x13, 0xcb, 0xa2, 0xcd, 0x85, 0x75, 0x10, 0x38, 0x98, 0x60, 0x5a, 0xc4, 0xd8, 0x3d, 0xc5, 0x8c, 0xfe, 0x66, 0x1e, 0xf6,  };
    uint8_t inputy[] = {0xf1, 0x17, 0x25, 0xc3, 0x63, 0x89, 0xb9, 0x59, 0xc1, 0xd4, 0x58, 0x51, 0x63, 0x8f, 0x32, 0x37, 0xe2, 0xb3, 0x72, 0xee, 0x86, 0xe6, 0x76, 0xa1, 0x54, 0x84, 0x69, 0xba, 0xe1, 0xbb, 0x79, 0x64,  };
    uint8_t expectedK[] = {0x04, 0x8d, 0x02, 0x06, 0xd2, 0x02, 0xce, 0xc5, 0x2d, 0x2a, 0xf7, 0x97, 0x72, 0x2b, 0x4f, 0x13, 0xbb, 0x86, 0x3a, 0x8e, 0x5f, 0x9f, 0x80, 0x15, 0x39, 0xd9, 0xae, 0xa9, 0xc5, 0x81, 0xd9, 0xc8, 0x61, 0x6c, 0x71, 0x53, 0xb8, 0xb9, 0x8b, 0x79, 0xf9, 0xbd, 0xf2, 0x42, 0x7c, 0x10, 0x9a, 0x8f, 0x88, 0x19, 0x48, 0x53, 0xfb, 0x20, 0xb3, 0x7d, 0x30, 0x04, 0x3c, 0x8d, 0x69, 0xdb, 0xa4, 0x4d, 0x28,  };

    int ret = 0;
    int curveIdx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* curveParams = wc_ecc_get_curve_params(curveIdx);
    mp_int groupA;
    mp_int groupPrime;
    mp_int groupOrder;
    ret = mp_init(&groupA);
    ret = mp_init(&groupPrime);
    ret = mp_init(&groupOrder);
    ret = mp_read_radix(&groupA, curveParams->Af, MP_RADIX_HEX);
    ret = mp_read_radix(&groupPrime, curveParams->prime, MP_RADIX_HEX);
    ret = mp_read_radix(&groupOrder, curveParams->order , MP_RADIX_HEX);

    ecc_point* M = wc_ecc_new_point();
    mp_int w;
    mp_int y;
    mp_init(&w);
    mp_init(&y);
    ecc_point* T = wc_ecc_new_point();
    ecc_point* K = wc_ecc_new_point();

    ret = wc_ecc_import_point_der(Mdata, sizeof(Mdata), curveIdx, M);
    if (ret < 0) {
        return false;
    }

    ret = wc_ecc_import_point_der(inputT, sizeof(inputT), curveIdx, T);

    mp_read_unsigned_bin(&w, inputw, sizeof(inputw));
    mp_read_unsigned_bin(&y, inputy, sizeof(inputy));

    ret = calculate_K(&groupA, &groupOrder, &groupPrime, &y, T, &w, M, K);

    uint8_t buffer[128];
    word32 outLen = sizeof(buffer);
    wc_ecc_export_point_der(curveIdx, K, buffer, &outLen);

    if (memcmp(buffer, expectedK, 65) != 0) {
        return false;
    }

    mp_free(&groupA);
    mp_free(&groupPrime);
    mp_free(&groupOrder);
    mp_free(&w);
    mp_free(&y);

    wc_ecc_del_point(M);
    wc_ecc_del_point(T);
    wc_ecc_del_point(K);

    return true;

}

bool password_hash_test()
{
    const char* password = "FFzeqrpJTVF4";
    const uint8_t expectedW[] = {0x2f, 0x75, 0x32, 0x7c, 0xcb, 0x81, 0xd0, 0x34, 0x0b, 0x8c, 0xe0, 0xc3, 0x13, 0xcb, 0xa2, 0xcd, 0x85, 0x75, 0x10, 0x38, 0x98, 0x60, 0x5a, 0xc4, 0xd8, 0x3d, 0xc5, 0x8c, 0xfe, 0x66, 0x1e, 0xf6 };

    int ret = 0;

    WC_RNG rng;
    ret = wc_InitRng(&rng);

    mp_int w;
    mp_init(&w);

    ret = password_to_mpi(password, &w, &rng);
    if (ret != 0) {
        return false;
    }

    uint8_t buffer[32];
    mp_to_unsigned_bin_len(&w, buffer, sizeof(buffer));

    if (sizeof(expectedW) != 32) {
        return false;
    }
    if (memcmp(buffer, expectedW, 32) != 0) {
        return false;
    }

    wc_FreeRng(&rng);
    mp_free(&w);


    return true;
}

bool nm_wolfssl_spake2_test()
{
    if (!nm_wolfssl_spake2_test_hash_mpi()) {
        return false;
    }
    if (!password_hash_test()) {
        return false;
    }
    if (!test_calculate_S()) {
        return false;
    }
    if (!test_calculate_K()) {
        return false;
    }
    return true;
}
