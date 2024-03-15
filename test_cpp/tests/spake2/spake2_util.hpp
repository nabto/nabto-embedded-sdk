#pragma once
#include <nabto/nabto_device_config.h>
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>

#include <array>

namespace nabto {
namespace test {

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


class Spake2Client {
 public:

    static int sha256(const unsigned char *input,
                    size_t ilen,
                    unsigned char *output)
    {
#if MBEDTLS_VERSION_MAJOR >= 3
        return mbedtls_sha256(input, ilen, output, 0);
#else
        return mbedtls_sha256_ret(input, ilen, output, 0);
#endif
    }

    Spake2Client(const std::string& password,
                 uint8_t* clientFp, uint8_t* deviceFp)
        : clientFp_(clientFp, clientFp+32), deviceFp_(deviceFp, deviceFp+32)
    {
        mbedtls_ecp_group_init(&grp_);
        mbedtls_ecp_group_load(&grp_, MBEDTLS_ECP_DP_SECP256R1);
        mbedtls_mpi_init(&x_);
        mbedtls_mpi_init(&w_);
        mbedtls_ecp_point_init(&M_);
        mbedtls_ecp_point_init(&N_);
        mbedtls_ecp_point_init(&K_);
        mbedtls_ecp_point_init(&T_);
        mbedtls_ecp_point_init(&S_);

        mbedtls_ecp_point_read_binary(&grp_, &M_, Mdata, sizeof(Mdata));
        mbedtls_ecp_point_read_binary(&grp_, &N_, Ndata, sizeof(Ndata));

        uint8_t wHash[32];
        sha256(
            reinterpret_cast<const uint8_t*>(password.data()), password.size(),
            wHash);

        mbedtls_mpi_read_binary(&w_, wHash, 32);
    }

    ~Spake2Client()
    {
        mbedtls_mpi_free(&x_);
        mbedtls_mpi_free(&w_);
        mbedtls_ecp_point_free(&M_);
        mbedtls_ecp_point_free(&N_);
        mbedtls_ecp_point_free(&K_);
        mbedtls_ecp_point_free(&T_);
        mbedtls_ecp_point_free(&S_);
        mbedtls_ecp_group_free(&grp_);
    }

    int calculateT(std::vector<uint8_t>& out)
    {
        mbedtls_ecp_point X;
        mbedtls_ecp_point_init(&X);

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ctr_drbg_init(&ctr_drbg);

        mbedtls_entropy_init(&entropy);
        int status = 0;
        status |= mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                        &entropy, NULL, 0);
        status |= mbedtls_ecp_gen_keypair(&grp_, &x_, &X,
                                          mbedtls_ctr_drbg_random, &ctr_drbg);

        mbedtls_mpi tmp;
        mbedtls_mpi_init(&tmp);
        status |= mbedtls_mpi_lset(&tmp, 1);

        // T = M*w + X*1
        status |= mbedtls_ecp_muladd(&grp_, &T_, &w_, &M_, &tmp, &X);

        writePoint(out, &grp_, &T_);

        mbedtls_mpi_free(&tmp);
        mbedtls_ecp_point_free(&X);
        return status;
    }

    int calculateK(uint8_t* S, size_t SLen)
    {
        int status = 0;
        status |= mbedtls_ecp_point_read_binary (&grp_, &S_, S, SLen);
        // K = x*(S-w*N) = x*S+((-x*w)*N)
        mbedtls_mpi tmp;
        mbedtls_mpi_init(&tmp);
        status |= mbedtls_mpi_lset(&tmp, -1);
        status |= mbedtls_mpi_mul_mpi(&tmp, &tmp, &x_);
        status |= mbedtls_mpi_mul_mpi(&tmp, &tmp, &w_);
        status |= mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp_.N);

        status |= mbedtls_ecp_muladd(&grp_, &K_, &x_, &S_, &tmp, &N_);
        mbedtls_mpi_free(&tmp);
        return status;
    }

    bool calculateKey()
    {
        // hash lengths and values of
        // public key fingerprint alice (client)
        // public key fingerprint bob (server/device)
        // T
        // S
        // K
        // w
        std::vector<uint8_t> T;
        std::vector<uint8_t> S;
        std::vector<uint8_t> K;
        std::vector<uint8_t> w;

        writePoint(T, &grp_, &T_);
        writePoint(S, &grp_, &S_);
        writePoint(K, &grp_, &K_);
        writeMpi(w, &w_);

        std::vector<uint8_t> toHash;
        encode(clientFp_, toHash);
        encode(deviceFp_, toHash);
        encode(T, toHash);
        encode(S, toHash);
        encode(K, toHash);
        encode(w, toHash);

        sha256(toHash.data(), toHash.size(), key_.data());
        return true;
    }

    void encode(std::vector<uint8_t> value, std::vector<uint8_t>& out)
    {
        uint32_t val = value.size();
        uint8_t b0 = (uint8_t)(val >> 24);
        uint8_t b1 = (uint8_t)(val >> 16);
        uint8_t b2 = (uint8_t)(val >> 8);
        uint8_t b3 = (uint8_t)val;
        out.push_back(b0);
        out.push_back(b1);
        out.push_back(b2);
        out.push_back(b3);
        std::copy(value.begin(), value.end(), std::back_inserter(out));
    }

    bool writePoint(std::vector<uint8_t>& out, mbedtls_ecp_group* g,
                    mbedtls_ecp_point* point)
    {
        size_t olen;
        uint8_t buffer[256];
        int status = mbedtls_ecp_point_write_binary(
            g, point, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buffer,
            sizeof(buffer));
        if (status != 0) {
            return false;
        }
        std::copy(buffer, buffer + olen, std::back_inserter(out));
        return true;
    }

    bool writeMpi(std::vector<uint8_t>& out, mbedtls_mpi* n)
    {
        size_t s = mbedtls_mpi_size(n);
        std::vector<uint8_t> buffer(s);

        int status = mbedtls_mpi_write_binary(n, buffer.data(), buffer.size());
        if (status != 0) {
            return false;
        }
        std::copy(buffer.begin(), buffer.end(), std::back_inserter(out));
        return true;
    }

    std::vector<uint8_t> clientFp_;
    std::vector<uint8_t> deviceFp_;
    std::string password_;
    mbedtls_ecp_group grp_;
    mbedtls_mpi w_;
    mbedtls_ecp_point M_;
    mbedtls_ecp_point N_;
    mbedtls_mpi x_;
    mbedtls_ecp_point K_;
    mbedtls_ecp_point T_;
    mbedtls_ecp_point S_;

    std::array<uint8_t, 32> key_;
};

}  // namespace test
}  // namespace nabto

#endif
