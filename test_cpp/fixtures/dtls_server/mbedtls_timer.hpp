#pragma once

#include <util/optional.hpp>

#include <boost/asio.hpp>

#include <chrono>

namespace nabto {

class MbedTlsTimer {
 public:
    MbedTlsTimer(boost::asio::io_context& io)
        : finalTimer_(io)
    {
    }

    ~MbedTlsTimer()
    {
        cancel();
    }

    void mbedSetTimer(uint32_t intermediateMilliseconds, uint32_t finalMilliseconds );
    int mbedGetTimer();

    void setCallback(std::function<void ()> timeoutCb) { timeoutCb_ = timeoutCb; }

    void cancel()
    {
        finalTimer_.cancel();
        timeoutCb_ = nullptr;
    }

 private:
    boost::asio::steady_timer finalTimer_;
    std::function<void ()> timeoutCb_;
    std::chrono::steady_clock::time_point intermediateTp_;
    lib::optional<std::chrono::steady_clock::time_point> finalTp_;

};

}
