#pragma once

#include <chrono>
#include <random>

namespace nabto {

class KeepAliveSettings {
 public:
    KeepAliveSettings()
    {
        std::random_device rd; // obtain a random number from hardware
        std::mt19937 eng(rd()); // seed the generator
        std::uniform_int_distribution<> distr(1800, 2200); // define the range
        keepAliveRetryInterval = std::chrono::milliseconds(distr(eng));
    }

    KeepAliveSettings(uint64_t interval, uint64_t retryInterval, uint64_t mr)
    {
        keepAliveInterval = std::chrono::milliseconds(interval);
        keepAliveRetryInterval = std::chrono::milliseconds(retryInterval);
        maxRetries = mr;
    }

    std::chrono::milliseconds keepAliveInterval = { std::chrono::seconds(30) };
    std::chrono::milliseconds keepAliveRetryInterval = { std::chrono::seconds(2) };
    uint64_t maxRetries = 15;


};

} // namespace
