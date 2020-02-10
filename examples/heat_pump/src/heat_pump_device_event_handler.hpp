#pragma once

#include <examples/common/abstract_device_event_handler.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpDeviceEventHandler : public common::AbstractDeviceEventHandler
{
 public:
    HeatPumpDeviceEventHandler(NabtoDevice* device)
        : common::AbstractDeviceEventHandler(device)
    {
    }
    static std::unique_ptr<HeatPumpDeviceEventHandler> create(NabtoDevice* device)
    {
        auto ptr = std::make_unique<HeatPumpDeviceEventHandler>(device);
        ptr->init();
        return std::move(ptr);
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
