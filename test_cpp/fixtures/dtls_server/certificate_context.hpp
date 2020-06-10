#pragma once

#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>

#include <memory>
#include <string>

namespace nabto {

class CertificateContext {
    CertificateContext();
 public:
    static std::shared_ptr<CertificateContext> create(const std::string& privateKey, const std::string& publicKey);

    ~CertificateContext();
    int authMode = MBEDTLS_SSL_VERIFY_OPTIONAL;
    mbedtls_x509_crt publicKey_;
    mbedtls_pk_context privateKey_;
};

typedef std::shared_ptr<CertificateContext> CertificateContextPtr;

} // namespace
