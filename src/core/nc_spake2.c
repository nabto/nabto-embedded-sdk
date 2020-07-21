#include "nc_spake2.h"
#include <mbedtls/sha256.h>

const uint8_t Mdata[] = { 0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f };
static uint8_t Ndata[] = { 0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49 };

int nc_spake2_init(struct nc_spake2_config* config)
{
    int status;
    mbedtls_ecp_group_init(&config->grp);
    status = mbedtls_ecp_group_load(&config->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (status != 0) {
        return status;
    }


    mbedtls_ecp_point_init(&config->M);
    mbedtls_ecp_point_init(&config->N);

    mbedtls_ecp_point_read_binary(&config->grp, &config->M, Mdata, sizeof(Mdata));
    mbedtls_ecp_point_read_binary(&config->grp, &config->N, Ndata, sizeof(Ndata));
    return 0;
}

void nc_spake2_deinit(struct nc_spake2_config* config)
{
    mbedtls_ecp_point_free(&config->N);
    mbedtls_ecp_point_free(&config->M);
    mbedtls_ecp_group_free(&config->grp);
}

int nc_spake2_password_to_mpi(const char* password, size_t passwordLength, mbedtls_mpi* w)
{
    uint8_t wHash[32];
    int status = mbedtls_sha256_ret((unsigned const char*)password, passwordLength, wHash, 0);
    if (status != 0) {
        return status;
    }
    mbedtls_mpi_read_binary(w, wHash, 32);
    return 0;
}

/**
 * Calculate K and S, given T and w.
 *
 * @param T  [in] The point T.
 * @param w  [in] The shared password hashed.
 * @param S  [out] The point S.
 * @param K  [out] The point K.
 */
int nc_spake2_server_round1(struct nc_spake2_config* config, mbedtls_ecp_point* T, mbedtls_mpi* w, mbedtls_ecp_point* S, mbedtls_ecp_point* K, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_ecp_point Y;
    mbedtls_mpi y;

    mbedtls_ecp_point_init(&Y);
    mbedtls_mpi_init(&y);

    // Y=G*y
    int status;
    status = mbedtls_ecp_gen_keypair( &config->grp, &y, &Y, f_rng, p_rng);
    if (status != 0) {
        return status;
    }

    // calculate S = w*N+Y

    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_lset(&tmp, 1);

    // S = N*w + Y*1
    mbedtls_ecp_muladd(&config->grp, S, w, &config->N, &tmp, &Y);

    // K = y*(T-w*M) = y*T - y*w*M
    // w = -w

    mbedtls_mpi_lset(&tmp, -1);

    mbedtls_mpi_mul_mpi(&tmp, &tmp, &y);
    mbedtls_mpi_mul_mpi(&tmp, &tmp, w);
    mbedtls_mpi_mod_mpi(&tmp, &tmp, &config->grp.N);

    // K = y*T+((-y*w)*M)
    mbedtls_ecp_muladd(&config->grp, K, &y, T, &tmp, &config->M);

    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&y);
    mbedtls_ecp_point_free(&Y);
    return 0;
}


int nc_spake2_client_round1_request(struct nc_spake2_config* config, struct mbedtls_mpi* w, mbedtls_mpi* x, mbedtls_ecp_point* T, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_ecp_point X;
    mbedtls_ecp_point_init(&X);
    // X=G*x
    int status;
    status = mbedtls_ecp_gen_keypair( &config->grp, x, &X, f_rng, p_rng);
    if (status != 0) {
        return status;
    }
    // T = w*M+X

    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_lset(&tmp, 1);

    // S = N*w + Y*1
    mbedtls_ecp_muladd(&config->grp, T, w, &config->M, &tmp, &X);

    mbedtls_mpi_free(&tmp);
    mbedtls_ecp_point_free(&X);
    return 0;

}

int nc_spake2_client_round1_response(struct nc_spake2_config* config, mbedtls_mpi* x, mbedtls_mpi* w, mbedtls_ecp_point* S, mbedtls_ecp_point* K)
{
    // x*(S-w*N) = x*S+((-x*w)*N)
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_lset(&tmp, -1);
    mbedtls_mpi_mul_mpi(&tmp, &tmp, x);
    mbedtls_mpi_mul_mpi(&tmp, &tmp, w);
    mbedtls_mpi_mod_mpi(&tmp, &tmp, &config->grp.N);

    mbedtls_ecp_muladd(&config->grp, K, x, S, &tmp, &config->N);

    return 0;
}
