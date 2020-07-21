#ifndef _NC_SPAKE2_H_
#define _NC_SPACE2_H_

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#ifdef __cplusplus
extern "C" {
#endif


struct nc_spake2_config {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point M;
    mbedtls_ecp_point N;
};

int nc_spake2_init(struct nc_spake2_config* config);
void nc_spake2_deinit(struct nc_spake2_config* config);

int nc_spake2_password_to_mpi(const char* password, size_t passwordLength, mbedtls_mpi* w);

int nc_spake2_server_round1(struct nc_spake2_config* config, mbedtls_ecp_point* T, mbedtls_mpi* w, mbedtls_ecp_point* S, mbedtls_ecp_point* K, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int nc_spake2_client_round1_response(struct nc_spake2_config* config, mbedtls_mpi* x, mbedtls_mpi* w, mbedtls_ecp_point* S, mbedtls_ecp_point* K);

int nc_spake2_client_round1_request(struct nc_spake2_config* config, struct mbedtls_mpi* w, mbedtls_mpi* x, mbedtls_ecp_point* T, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

#ifdef __cplusplus
} // extern "C"
#endif



#endif
