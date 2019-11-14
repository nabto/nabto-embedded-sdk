#include "tcptunnel.hpp"

#include "json_config.hpp"

#include <nabto/nabto_device_experimental.h>

#include <iostream>

void TcpTunnel::iamChanged(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    if (err != NABTO_DEVICE_EC_OK) {
        return;
    }
    TcpTunnel* hp = (TcpTunnel*)userData;
    hp->saveConfig();
    hp->listenForIamChanges();
}

void TcpTunnel::listenForIamChanges()
{
    nabto_device_iam_listen_for_changes(device_, iamChangedFuture_, currentIamVersion_);
    nabto_device_future_set_callback(iamChangedFuture_, TcpTunnel::iamChanged, this);
}


void TcpTunnel::startWaitEvent()
{
    nabto_device_listener_connection_event(connectionEventListener_, connectionEventFuture_, &connectionRef_, &connectionEvent_);
    nabto_device_future_set_callback(connectionEventFuture_, &TcpTunnel::connectionEvent, this);
}

void TcpTunnel::connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    TcpTunnel* tt = (TcpTunnel*)userData;
    if (err != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        if (tt->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_OPENED) {
            std::cout << "Connection " << tt->connectionRef_ << ": opened" << std::endl;
        } else if (tt->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CLOSED) {
            std::cout << "Connection " << tt->connectionRef_ << ": closed" << std::endl;
        } else if (tt->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED) {
            std::cout << "Connection " << tt->connectionRef_ << ": changed channel" << std::endl;
        }
    }
    tt->startWaitEvent();

}

void TcpTunnel::listenForConnectionEvents()
{
    NabtoDeviceError ec = nabto_device_connection_events_init_listener(device_, connectionEventListener_);
    if (ec) {
        std::cerr << "Failed to initialize connection events listener" << std::endl;
        return;
    }
    startWaitEvent();
}

void TcpTunnel::startWaitDevEvent()
{
    nabto_device_listener_device_event(deviceEventListener_, deviceEventFuture_, &deviceEvent_);
    nabto_device_future_set_callback(deviceEventFuture_, &TcpTunnel::deviceEvent, this);
}

void TcpTunnel::deviceEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    TcpTunnel* tt = (TcpTunnel*)userData;
    if (err != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        if (tt->deviceEvent_ == NABTO_DEVICE_EVENT_ATTACHED) {
            std::cout << "Device is attached to the basestation" << std::endl;
        } else if (tt->deviceEvent_ == NABTO_DEVICE_EVENT_DETACHED) {
            std::cout << "Device is detached from the basestation" << std::endl;
        }
    }
    tt->startWaitDevEvent();

}

void TcpTunnel::listenForDeviceEvents()
{
    NabtoDeviceError ec = nabto_device_device_events_init_listener(device_, deviceEventListener_);
    if (ec) {
        std::cerr << "Failed to initialize device events listener" << std::endl;
        return;
    }
    startWaitDevEvent();
}

void TcpTunnel::saveConfig()
{
    json config = config_;

    uint64_t version;
    size_t used;
    if (nabto_device_iam_dump(device_, &version, NULL, 0, &used) != NABTO_DEVICE_EC_OUT_OF_MEMORY) {
        return;
    }

    std::vector<uint8_t> buffer(used);
    if(nabto_device_iam_dump(device_, &version, buffer.data(), buffer.size(), &used) != NABTO_DEVICE_EC_OK) {
        return;
    }
    config["Iam"] = json::from_cbor(buffer);
    currentIamVersion_ = version;

    json_config_save(configFile_, config);
    std::cout << "Configuration saved to file" << std::endl;
}
