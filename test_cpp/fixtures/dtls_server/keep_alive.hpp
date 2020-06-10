#pragma once

#include "keep_alive_settings.hpp"

#include <util/error_code.hpp>
#include <util/span.hpp>

#include <cstdint>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <random>

namespace nabto {

class KeepAlive {
 public:

    typedef enum {
        DO_NOTHING,
        SEND_KA,
        KA_TIMEOUT,
        KA_STOPPED
    } Action;

    KeepAlive(boost::asio::io_context& io, KeepAliveSettings settings);

    ~KeepAlive();
    void stop();

    void setKeepAliveSettings(const KeepAliveSettings& kas) {
        settings_ = kas;
    }

    /**
     * Wait on next time to maybe send a keep alive.
     */
    void asyncWaitSendKeepAlive(std::function<void (const lib::error_code& ec)> cb);

    /**
     * Test if we should send a keep alive.
     *
     * if we return true, send a keep alive packet, else wait for next
     * time to call the test.
     */
    Action shouldSendKeepAlive(uint64_t recvCount, uint64_t sendCount);

    static bool isKeepAliveRequest(lib::span<const uint8_t> received);
    static bool isKeepAliveResponse(lib::span<const uint8_t> received);
    static std::shared_ptr<std::vector<uint8_t> > createKeepAliveResponse(lib::span<const uint8_t> packet);
    static std::shared_ptr<std::vector<uint8_t> > createKeepAliveRequest(uint64_t seq);

 private:
    boost::asio::steady_timer keepAliveTimer_;

    KeepAliveSettings settings_;

    uint64_t lastRecvCount_ = 0;
    uint64_t lastSentCount_ = 0;

    uint64_t lostKeepAlives_ = 0;
    bool stopped_ = false;
};

}
