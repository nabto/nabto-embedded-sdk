#include "keep_alive.hpp"
#include "dtls_error_codes.hpp"

namespace nabto {

enum class ApplicationDataType : uint8_t {
    KEEP_ALIVE = 4,
    STREAMING = 5
};

enum class KeepAliveContentType : uint8_t {
    KEEP_ALIVE_REQUEST = 3,
    KEEP_ALIVE_RESPONSE = 4
};

KeepAlive::KeepAlive(boost::asio::io_context& io, KeepAliveSettings settings)
    : keepAliveTimer_(io),
      settings_(settings)
{

}

KeepAlive::~KeepAlive()
{
    stop();
}

void KeepAlive::stop()
{
    stopped_ = true;
    keepAliveTimer_.cancel();
}

/**
 * Wait on next time to maybe send a keep alive.
 */
void KeepAlive::asyncWaitSendKeepAlive(std::function<void (const lib::error_code& ec)> cb)
{
    if (stopped_) {
        cb(make_error_code(DtlsError::closed));
    }
    keepAliveTimer_.expires_after(settings_.keepAliveRetryInterval);
    keepAliveTimer_.async_wait([cb](const boost::system::error_code& ec){
            cb(ec);
        });
}

/**
 * Test if we should send a keep alive.
 *
 * @return
 * DO_NOTHING: wait for next KA timeout.
 * SEND_KA: send a keep alive and wait for next timeout.
 * KA_TIMEOUT: close the connection. it's dead.
 */
KeepAlive::Action KeepAlive::shouldSendKeepAlive(uint64_t recvCount, uint64_t sentCount)
{
    if (stopped_) {
        return KA_STOPPED;
    }
    uint64_t skipKeepAliveIntervals = settings_.keepAliveInterval / settings_.keepAliveRetryInterval;

    if (lostKeepAlives_ > (settings_.maxRetries + skipKeepAliveIntervals)) {
        return KA_TIMEOUT;
    }

    if (recvCount > lastRecvCount_ && sentCount > lastSentCount_) {
        lostKeepAlives_ = 0;
        lastRecvCount_ = recvCount;
        lastSentCount_ = sentCount;
    } else {
        lostKeepAlives_++;
    }

    if (lostKeepAlives_ > skipKeepAliveIntervals) {
        return SEND_KA;
    } else {
        return DO_NOTHING;
    }
}

// static
bool KeepAlive::isKeepAliveRequest(lib::span<const uint8_t> received)
{
    return (received.size() >= 18 &&
            received.data()[0] == static_cast<uint8_t>(ApplicationDataType::KEEP_ALIVE) &&
            received.data()[1] == static_cast<uint8_t>(KeepAliveContentType::KEEP_ALIVE_REQUEST));
}

bool KeepAlive::isKeepAliveResponse(lib::span<const uint8_t> received)
{
    return (received.size() >= 18 &&
            received.data()[0] == static_cast<uint8_t>(ApplicationDataType::KEEP_ALIVE) &&
            received.data()[1] == static_cast<uint8_t>(KeepAliveContentType::KEEP_ALIVE_RESPONSE));
}

//static
std::shared_ptr<std::vector<uint8_t> > KeepAlive::createKeepAliveResponse(lib::span<const uint8_t> packet)
{
    auto keepAliveResponse = std::make_shared<std::vector<uint8_t> >();
    lib::span<const uint8_t> keepAliveSeq(packet.data()+2, 16);

    keepAliveResponse->push_back(static_cast<uint8_t>(ApplicationDataType::KEEP_ALIVE));
    keepAliveResponse->push_back(static_cast<uint8_t>(KeepAliveContentType::KEEP_ALIVE_RESPONSE));
    std::copy(keepAliveSeq.begin(), keepAliveSeq.end(), std::back_inserter(*keepAliveResponse));

    return keepAliveResponse;
}

//static
std::shared_ptr<std::vector<uint8_t> > KeepAlive::createKeepAliveRequest(uint64_t seq)
{
    auto keepAlivePacket = std::make_shared<std::vector<uint8_t> >();
    keepAlivePacket->push_back(static_cast<uint8_t>(ApplicationDataType::KEEP_ALIVE));
    keepAlivePacket->push_back(static_cast<uint8_t>(KeepAliveContentType::KEEP_ALIVE_REQUEST));

    for (int i = 0; i < 8; i++) {
        uint8_t b = (uint8_t)seq;
        seq = seq << 1;
        keepAlivePacket->push_back((uint8_t)b);
    }

    for (int i = 0; i < 8; i++) {
        keepAlivePacket->push_back(0);
    }

    return keepAlivePacket;
}


}
