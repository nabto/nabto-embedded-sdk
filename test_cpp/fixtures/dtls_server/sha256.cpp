#include "sha256.hpp"

#include <mbedtls/sha256.h>

namespace nabto {

std::array<uint8_t, 32> Sha256::sha256(lib::span<uint8_t> data)
{
    std::array<uint8_t, 32> out;
#if MBEDTLS_VERSION_MAJOR >= 3
    mbedtls_sha256(data.data(), data.size(), out.data(), 0);
#else
    mbedtls_sha256_ret(data.data(), data.size(), out.data(), 0);
#endif
    return out;
}

std::array<uint8_t, 16> Sha256::sha256Truncated(lib::span<uint8_t> data)
{
    std::array<uint8_t, 32> full = sha256(data);
    std::array<uint8_t, 16> truncated;
    std::copy(full.begin(), full.begin()+16, truncated.begin());
    return truncated;
}

}
