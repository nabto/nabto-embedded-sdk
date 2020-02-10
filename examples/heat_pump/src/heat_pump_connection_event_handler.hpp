#pragma once

#include <examples/common/abstract_connection_event_handler.hpp>

#include <iostream>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpConnectionEventHandler : public common::AbstractConnectionEventHandler
{
 public:
    HeatPumpConnectionEventHandler(NabtoDevice* device)
        : common::AbstractConnectionEventHandler(device)
    {
    }

    static std::unique_ptr<HeatPumpConnectionEventHandler> create(NabtoDevice* device)
    {
        auto ptr = std::make_unique<HeatPumpConnectionEventHandler>(device);
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

} } }
