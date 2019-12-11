#pragma once

#include <nabto/nabto_device.h>

#include <array>

namespace nabto {
namespace test {

class EchoHandler {
 public:
    EchoHandler(NabtoDevice* device, NabtoDeviceStream* stream)
        : stream_(stream)
    {
        future_ = nabto_device_future_new(device);
    }

    ~EchoHandler() {
        nabto_device_future_free(future_);
    }
    void start() {
        if (future_ == NULL) {
            end();
            return;
        }

        accept();
    }

    void accept()
    {
        nabto_device_stream_accept(stream_, future_);
        nabto_device_future_set_callback(future_, &EchoHandler::accepted, this);
    }

    static void accepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // Accept should not fail
            return eh->end();
        } else {
            eh->startRead();
        }
    }

    void startRead() {
        nabto_device_stream_read_some(stream_, future_, recvBuffer_.data(), recvBuffer_.size(), &transferred_);
        nabto_device_future_set_callback(future_, &EchoHandler::read, this);
    }

    static void read(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // read failed probably eof, close stream
            eh->close();
        } else {
            eh->startWrite();
        }
    }

    void startWrite() {
        nabto_device_stream_write(stream_, future_, recvBuffer_.data(), transferred_);
        nabto_device_future_set_callback(future_, &EchoHandler::written, this);
    }

    static void written(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // write should not fail, goto error
            eh->error();
            return;
        } else {
            eh->startRead();
        }
    }

    void close() {
        nabto_device_stream_close(stream_, future_);
        nabto_device_future_set_callback(future_, &EchoHandler::closed, this);
    }

    static void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData) {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // close should not fail
        }
        eh->end();
    }

    void error() {
        end();
    }

    void end() {
        nabto_device_stream_free(stream_);
        free(this);
    }

 private:
    NabtoDeviceStream* stream_;
    std::array<uint8_t, 1024> recvBuffer_;
    std::size_t transferred_;
    NabtoDeviceFuture* future_;
};

class EchoListener {
 public:
    EchoListener(NabtoDevice* device)
        : device_(device)
    {
        listener_ = nabto_device_listener_new(device_);
        nabto_device_stream_init_listener(device_, listener_, 42);
        listenFuture_ = nabto_device_future_new(device_);
    }
    ~EchoListener() {
        nabto_device_listener_free(listener_);
        nabto_device_future_free(listenFuture_);
    }
    void startListen()
    {
        nabto_device_listener_new_stream(listener_, listenFuture_, &listenStream_);
        nabto_device_future_set_callback(listenFuture_, &EchoListener::newStream, this);
    }

    static void newStream(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoListener* el = (EchoListener*)userData;
        if (ec) {
            return;
        }
        EchoHandler* eh = new EchoHandler(el->device_, el->listenStream_);
        eh->start();
        // TODO: this potentially overwrites listenStream_ resource
        el->startListen();
    }

 private:
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* listenFuture_;
    NabtoDeviceStream* listenStream_;
    NabtoDevice* device_;
};

} } // namespace
