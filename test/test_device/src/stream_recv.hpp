#pragma once

#include <nabto/nabto_device.h>

#include <array>

namespace nabto {
namespace test {

/**
 * Read all incoming data until the stream is closed.  Close the
 * stream in the start to inform the other end that this handler will
 * not send any data.
 */
class RecvHandler {
 public:
    RecvHandler(NabtoDevice* device, NabtoDeviceStream* stream)
        : stream_(stream)
    {
        future_ = nabto_device_future_new(device);
    }
    ~RecvHandler() {
        nabto_device_future_free(future_);
    }
    void start()
    {
        if (future_ == NULL) {
            end();
            return;
        }
        accept();
    }

    void accept()
    {
        nabto_device_stream_accept(stream_, future_);
        nabto_device_future_set_callback(future_, &RecvHandler::accepted, this);
    }

    static void accepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvHandler* rh = (RecvHandler*)userData;
        if (ec) {
            // Accept should not fail
            return rh->end();
        } else {
            rh->close();
        }
    }

    void close()
    {
        nabto_device_stream_close(stream_, future_);
        nabto_device_future_set_callback(future_, &RecvHandler::closed, this);
    }

    static void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvHandler* rh = (RecvHandler*)userData;
        if (ec) {
            // this should not fail.
            return rh->end();
        }
        rh->startRead();
    }

    void startRead()
    {
        nabto_device_stream_read_some(stream_, future_, recvBuffer_.data(), recvBuffer_.size(), &transferred_);
        nabto_device_future_set_callback(future_, &RecvHandler::read, this);
    }

    static void read(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvHandler* rh = (RecvHandler*)userData;
        if (ec) {
            // probably eof
            return rh->end();
        }
        rh->totalTransferred_ += rh->transferred_;
        rh->startRead();
    }

    void end() {
        std::cout << "Recv stream end transferred: " << totalTransferred_ << std::endl;
        nabto_device_stream_free(stream_);
        free(this);
    }

 private:
    NabtoDeviceStream* stream_;
    std::array<uint8_t, 1024> recvBuffer_;
    std::size_t transferred_;
    std::size_t totalTransferred_ = 0;
    NabtoDeviceFuture* future_;
};


class RecvListener {
 public:
    RecvListener(NabtoDevice* device)
        : device_(device)
    {
        listener_ = nabto_device_listener_new(device_);
        nabto_device_stream_init_listener(device_, listener_, 43);
        listenFuture_ = nabto_device_future_new(device_);
    }
    ~RecvListener() {
        nabto_device_listener_free(listener_);
        nabto_device_future_free(listenFuture_);
    }
    void startListen()
    {
        nabto_device_listener_new_stream(listener_, listenFuture_, &listenStream_);
        nabto_device_future_set_callback(listenFuture_, &RecvListener::newStream, this);
    }

    static void newStream(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvListener* rl = (RecvListener*)userData;
        if (ec) {
            return;
        }
        RecvHandler* rh = new RecvHandler(rl->device_, rl->listenStream_);
        rh->start();
        // TODO: this potentially overwrites listenStream_
        rl->startListen();
    }

 private:
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* listenFuture_;
    NabtoDeviceStream* listenStream_;
    NabtoDevice* device_;
};

} } // namespace
