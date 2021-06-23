#include "mbedtls_util.hpp"
#include "sha256.hpp"

#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

#include <string>
#include <algorithm>
#include <vector>

#include <iostream>
#include <string.h>

namespace nabto {

static void removeNewline(std::string &s) {
    s.erase(std::find_if_not(s.rbegin(), s.rend(), [](int ch) {
                return ch == '\n';
            }).base(), s.end());
}

void mbedTlsLogger( void *ctx, int level,
                    const char *file, int line,
                    const char *str )
{
    (void)ctx;
    size_t fileLen = strlen(file);
    char fileTmp[32+4];
    if(fileLen > 32) {
        strcpy(fileTmp, "...");
        strcpy(fileTmp + 3, file + fileLen - 32);
    } else {
        strcpy(fileTmp, file);
    }
    std::string dbgStr(str);
    removeNewline(dbgStr);

    std::cout << fileTmp << "(" << line << ")[" << level << "]" << dbgStr << std::endl;
}

std::string mbedTlsStrError(int ret)
{
    char buffer[1024];
    mbedtls_strerror(ret, buffer, sizeof(buffer));
    return std::string(buffer);

}

lib::optional<std::array<uint8_t, 32> > getFingerprintFromPeer(const mbedtls_x509_crt* crt)
{
    uint8_t buffer[256];
    mbedtls_pk_context *ctx = const_cast<mbedtls_pk_context*>(&crt->pk);
    int len = mbedtls_pk_write_pubkey_der( ctx, buffer, sizeof(buffer));
    if (len <= 0) {
        return lib::nullopt;
    }

    return nabto::Sha256::sha256(lib::span<uint8_t>((buffer+sizeof(buffer))-len, len));
}

lib::optional<std::array<uint8_t, 32> > getFingerprintFromPem(const std::string& publicKeyPem)
{
    lib::optional<std::array<uint8_t, 32> > ret;
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);

    int status = mbedtls_x509_crt_parse(&chain, reinterpret_cast<const unsigned char*>(publicKeyPem.c_str()), publicKeyPem.size()+1);
    if (status != 0) {
    } else {
        ret = nabto::getFingerprintFromPeer(&chain);
    }

    mbedtls_x509_crt_free(&chain);
    return ret;
}

lib::optional<std::string> publicKeyFromPrivateKey(const std::string& privateKey)
{
    // 1. load key from pem
    // 2. create crt
    // 3. write crt to pem string.
    std::string returnValue;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;

    int ret;

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        return lib::nullopt;
    }

    ret = mbedtls_pk_parse_key( &key, (const unsigned char*)privateKey.c_str(), privateKey.size()+1, NULL, 0 );
    if (ret != 0) {
        return lib::nullopt;
    }

    // initialize crt
    mbedtls_x509write_crt_set_subject_key( &crt, &key );
    mbedtls_x509write_crt_set_issuer_key( &crt, &key );

    ret = mbedtls_mpi_read_string( &serial, 10, "1");
    if (ret != 0) {
        return lib::nullopt;
    }

    mbedtls_x509write_crt_set_serial( &crt, &serial );

    ret = mbedtls_x509write_crt_set_subject_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return lib::nullopt;
    }

    ret = mbedtls_x509write_crt_set_issuer_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return lib::nullopt;
    }

    mbedtls_x509write_crt_set_version( &crt, 2 );
    mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );

    ret = mbedtls_x509write_crt_set_validity( &crt, "20010101000000", "20491231235959" );
    if (ret != 0) {
        return lib::nullopt;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints( &crt, 1, -1);
    if (ret != 0) {
        return lib::nullopt;
    }

    {
        // write crt
        std::array<char, 1024> crtPemBuffer;

        ret = mbedtls_x509write_crt_pem( &crt, (unsigned char*)crtPemBuffer.data(), crtPemBuffer.size(),
                                         mbedtls_ctr_drbg_random, &ctr_drbg );

        if (ret != 0) {
            return lib::nullopt;
        }

        returnValue = std::string(crtPemBuffer.data());
    }

    // TODO cleanup in case of error
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&key);
    return returnValue;
}

void mbedTlsSetDebugLevelFromEnv()
{
    unsigned int level = 0;

    const char* debugLevel = std::getenv("MBEDTLS_DEBUG_LEVEL");
    if (debugLevel) {
        try {
            level = atoi(debugLevel);
            if (level <= 4) {
                mbedtls_debug_set_threshold( level );
            }
        } catch (...) {

        }
    }
}

std::string createPrivateKey()
{
    std::vector<uint8_t> output_buf(1024);
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    std::string pers = "gen_key";
    std::string result = "";

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );

    if( (mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                reinterpret_cast<const uint8_t*>(pers.c_str()),
                                pers.size() ) != 0) ||
        (mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) != 0 ) ||
        (mbedtls_ecp_gen_key( MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec( key ),
                              mbedtls_ctr_drbg_random, &ctr_drbg ) != 0) ||
        (mbedtls_pk_write_key_pem( &key, output_buf.data(), output_buf.size() ) != 0 ))
    {
        // generating the private key failed
    } else {
        result = std::string(reinterpret_cast<const char*>(output_buf.data()));
    }

    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return result;
}

} // namespace
