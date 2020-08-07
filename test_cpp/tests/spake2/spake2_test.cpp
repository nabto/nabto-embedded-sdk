#include <boost/test/unit_test.hpp>
#include <core/nc_spake2.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


BOOST_AUTO_TEST_SUITE(spake2)

// BOOST_AUTO_TEST_CASE(init_deinit)
// {
//     nc_spake2_config config;
//     BOOST_TEST(nc_spake2_init(&config) == 0);
//     nc_spake2_deinit(&config);
// }

// BOOST_AUTO_TEST_CASE(round1)
// {
//     nc_spake2_config config;
//     BOOST_TEST(nc_spake2_init(&config) == 0);

//     mbedtls_mpi w;
//     mbedtls_mpi_init(&w);
//     const char* password = "foobar";
//     BOOST_TEST(nc_spake2_password_to_mpi(password, strlen(password), &w) == 0);

//     mbedtls_entropy_context entropy;
//     mbedtls_ctr_drbg_context ctr_drbg;
//     mbedtls_ctr_drbg_init(&ctr_drbg);
//     mbedtls_entropy_init(&entropy);

//     mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
//                            NULL, 0);


//     mbedtls_mpi x;
//     mbedtls_ecp_point T;
//     mbedtls_mpi_init(&x);
//     mbedtls_ecp_point_init(&T);

//     BOOST_TEST(nc_spake2_client_round1_request(&config, &w, &x, &T, mbedtls_entropy_func, &entropy) == 0);

//     mbedtls_ecp_point S;
//     mbedtls_ecp_point serverK;
//     mbedtls_ecp_point clientK;
//     mbedtls_ecp_point_init(&S);
//     mbedtls_ecp_point_init(&serverK);
//     mbedtls_ecp_point_init(&clientK);

//     BOOST_TEST(nc_spake2_server_round1(&config, &T, &w, &S, &serverK, mbedtls_entropy_func, &entropy) == 0);

//     BOOST_TEST(nc_spake2_client_round1_response(&config, &x, &w, &S, &clientK) == 0);

//     BOOST_TEST(mbedtls_ecp_point_cmp(&clientK, &serverK) == 0);

//     nc_spake2_deinit(&config);
// }

BOOST_AUTO_TEST_SUITE_END()
