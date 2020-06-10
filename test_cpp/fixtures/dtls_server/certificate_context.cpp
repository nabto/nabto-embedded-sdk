#include "certificate_context.hpp"

#include "mbedtls_util.hpp"

namespace nabto {

CertificateContext::CertificateContext()
{
    mbedtls_x509_crt_init( &publicKey_ );
    mbedtls_pk_init( &privateKey_ );
}

CertificateContext::~CertificateContext()
{
    mbedtls_pk_free(&privateKey_);
    mbedtls_x509_crt_free(&publicKey_);
}

std::shared_ptr<CertificateContext> CertificateContext::create(const std::string& privateKeyPem, const std::string& publicKeyPem)
{
    auto ctx = std::shared_ptr<CertificateContext>(new CertificateContext());
    int ret;
    ret = mbedtls_x509_crt_parse( &ctx->publicKey_, reinterpret_cast<const unsigned char*>(publicKeyPem.c_str()), publicKeyPem.size()+1);
    if( ret != 0 )
    {
        //Log::get("dtls_server")->error("mbedtls_x509_crt_parse returned {0:d} {1}", ret, mbedTlsStrError(ret));
        return nullptr;
    }

    ret =  mbedtls_pk_parse_key( &ctx->privateKey_, reinterpret_cast<const unsigned char*>(privateKeyPem.c_str()), privateKeyPem.size()+1, NULL, 0 );
    if( ret != 0 )
    {
        //Log::get("dtls_server")->error("mbedtls_pk_parse_key returned {0:d} {1}", ret, mbedTlsStrError(ret));
        return nullptr;
    }



    return ctx;

}

} // namespace
