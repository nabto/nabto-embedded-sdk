#include "mbedtls_timer.hpp"

namespace nabto {

void MbedTlsTimer::mbedSetTimer(uint32_t intermediateMilliseconds, uint32_t finalMilliseconds )
{
    if(!timeoutCb_) {
        return;
    }
    if (finalMilliseconds == 0) {
        // disable current timer;
        boost::system::error_code ec;
        finalTimer_.cancel(ec);
        finalTp_ = boost::none;
    } else {
        intermediateTp_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(intermediateMilliseconds);
        finalTp_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(finalMilliseconds);

        finalTimer_.cancel();
        finalTimer_.expires_at(*(finalTp_));
        finalTimer_.async_wait([this](const boost::system::error_code& ec){
                if (ec) {

                } else {
                    auto cb = timeoutCb_;
                    if (cb) {
                        timeoutCb_();
                    }
                }
            });
    }
}

int MbedTlsTimer::mbedGetTimer()
{
    if (finalTp_) {
        if (std::chrono::steady_clock::now() > *(finalTp_)) {
            return 2;
        } else if (std::chrono::steady_clock::now() > intermediateTp_) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}

}
