#pragma once

#include "abstract_device_event_handler.hpp"

#include <iostream>

namespace nabto {
namespace examples {
namespace common {

class StdoutDeviceEventHandler : public AbstractDeviceEventHandler
{
 public:
    StdoutDeviceEventHandler(NabtoDevice* device)
        : AbstractDeviceEventHandler(device)
    {
    }
    static std::unique_ptr<StdoutDeviceEventHandler> create(NabtoDevice* device)
    {
        auto ptr = std::make_unique<StdoutDeviceEventHandler>(device);
        ptr->init();
        return ptr;
    }
    virtual void handleDeviceEvent(NabtoDeviceEvent event)
    {
        if (event == NABTO_DEVICE_EVENT_ATTACHED) {
            std::cout << "Device is now attached" << std::endl;
        } else if (event == NABTO_DEVICE_EVENT_DETACHED) {
            std::cout << "Device is now detached" << std::endl;
        } else {
            std::cout << "Unknown device event: " << event << std::endl;
        }
    }
 private:
};

} } } // namespace
