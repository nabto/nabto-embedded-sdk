#pragma once

#include "abstract_connection_event_handler.hpp"

#include <iostream>

namespace nabto {
namespace examples {
namespace common {

class StdoutConnectionEventHandler : public AbstractConnectionEventHandler
{
 public:
     StdoutConnectionEventHandler(NabtoDevice* device)
        : AbstractConnectionEventHandler(device)
    {
    }

    static std::unique_ptr<StdoutConnectionEventHandler> create(NabtoDevice* device)
    {
        auto ptr = std::make_unique<StdoutConnectionEventHandler>(device);
        ptr->init();
        return std::move(ptr);
    }

    virtual void handleConnectionEvent(NabtoDeviceConnectionRef ref, NabtoDeviceConnectionEvent event)
    {
        if (event == NABTO_DEVICE_CONNECTION_EVENT_OPENED) {
            std::cout << "New connection opened with reference: " << ref << std::endl;
        } else if (event == NABTO_DEVICE_CONNECTION_EVENT_CLOSED) {
            std::cout << "Connection with reference: " << ref << " was closed" << std::endl;
        } else if (event == NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED) {
            std::cout << "Connection with reference: " << ref << " changed channel" << std::endl;
        } else {
            std::cout << "Unknown connection event: " << event << " on connection reference: " << ref << std::endl;
        }
    }
};

} } } // namespace
