#include "certificate_context.hpp"

#include "mbedtls_util.hpp"

namespace nabto {

CertificateContext::CertificateContext()
{
    mbedtls_x509_crt_init( &publicKey_ );
    mbedtls_pk_init( &privateKey_ );
    mbedtls_entropy_init( &entropy_ );
    mbedtls_ctr_drbg_init( &ctrDrbg_ );
}

CertificateContext::~CertificateContext()
{
    mbedtls_pk_free(&privateKey_);
    mbedtls_x509_crt_free(&publicKey_);
    mbedtls_ctr_drbg_free( &ctrDrbg_ );
    mbedtls_entropy_free( &entropy_ );
}

std::shared_ptr<CertificateContext> CertificateContext::create(const std::string& privateKeyPem, const std::string& publicKeyPem)
{
    int ret;
    auto ctx = std::shared_ptr<CertificateContext>(new CertificateContext());
    if (ctx == nullptr) {
        return nullptr;
    }
    ret = mbedtls_ctr_drbg_seed( &ctx->ctrDrbg_, mbedtls_entropy_func, &ctx->entropy_, NULL, 0);
    if ( ret != 0) {
        return nullptr;
    }
    ret = mbedtls_x509_crt_parse( &ctx->publicKey_, reinterpret_cast<const unsigned char*>(publicKeyPem.c_str()), publicKeyPem.size()+1);
    if( ret != 0 )
    {
        //Log::get("dtls_server")->error("mbedtls_x509_crt_parse returned {0:d} {1}", ret, mbedTlsStrError(ret));
        return nullptr;
    }

    const unsigned char* p = reinterpret_cast<const unsigned char*>(privateKeyPem.c_str());
    size_t pLen = privateKeyPem.size() + 1;

#if MBEDTLS_VERSION_MAJOR >= 3
    ret =  mbedtls_pk_parse_key( &ctx->privateKey_, p, pLen, NULL, 0, mbedtls_ctr_drbg_random, &ctx->ctrDrbg_);
#else
    ret =  mbedtls_pk_parse_key( &ctx->privateKey_, p, pLen, NULL, 0);
#endif
    if( ret != 0 )
    {
        //Log::get("dtls_server")->error("mbedtls_pk_parse_key returned {0:d} {1}", ret, mbedTlsStrError(ret));
        return nullptr;
    }



    return ctx;

}

} // namespace
