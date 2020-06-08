#pragma once

#include <util/optional.hpp>

#include <mbedtls/x509_crt.h>

#include <string>

namespace nabto {

class MbedTlsLogCtx
{
 public:
    MbedTlsLogCtx(const std::string& moduleName)
        : moduleName_(moduleName)
    {
    }
    std::string moduleName_;
};

void mbedTlsLogger( void *ctx, int level,
                    const char *file, int line,
                    const char *str );

std::string mbedTlsStrError(int ret);

lib::optional<std::array<uint8_t, 32> > getFingerprintFromPeer(const mbedtls_x509_crt* crt);
lib::optional<std::array<uint8_t, 32> > getFingerprintFromPem(const std::string& publicKeyPem);
lib::optional<std::string> publicKeyFromPrivateKey(const std::string& privateKey);

void mbedTlsSetDebugLevelFromEnv();

std::string createPrivateKey();

} // namespace
