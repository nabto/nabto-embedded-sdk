#pragma once

#include <util/span.hpp>

#include <array>

namespace nabto {


class Sha256 {
 public:
    static std::array<uint8_t, 32> sha256(lib::span<uint8_t> data);
    static std::array<uint8_t, 16> sha256Truncated(lib::span<uint8_t> data);
};

} // namespace
