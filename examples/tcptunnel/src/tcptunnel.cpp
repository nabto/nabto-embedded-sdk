#include "tcptunnel.hpp"

#include "json_config.hpp"

#include <nabto/nabto_device_experimental.h>

#include <iostream>

void TcpTunnel::iamChanged(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    nabto_device_future_free(fut);
    if (err != NABTO_DEVICE_EC_OK) {
        return;
    }
    TcpTunnel* hp = (TcpTunnel*)userData;
    hp->saveConfig();
    hp->listenForIamChanges();
}

void TcpTunnel::listenForIamChanges()
{
    NabtoDeviceFuture* future = nabto_device_iam_listen_for_changes(device_, currentIamVersion_);
    if (!future) {
        return;
    }
    nabto_device_future_set_callback(future, TcpTunnel::iamChanged, this);
}


void TcpTunnel::startWaitEvent()
{
    NabtoDeviceFuture* future;
    // TODO: consider dynamical resources
    NabtoDeviceError ec = nabto_device_listener_connection_event(connectionEventListener_, &future, &connectionRef_, &connectionEvent_);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to create connection event future with ec: " << ec << std::endl;
        nabto_device_listener_free(connectionEventListener_);
        connectionEventListener_ = NULL;
        return;
    }
    ec = nabto_device_future_set_callback(future, &TcpTunnel::connectionEvent, this);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to set future callback with ec: " << ec << std::endl;
        nabto_device_future_free(future);
        nabto_device_listener_free(connectionEventListener_);
        connectionEventListener_ = NULL;
        return;
    }
}

void TcpTunnel::connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    TcpTunnel* tt = (TcpTunnel*)userData;
    nabto_device_future_free(fut);
    if (err != NABTO_DEVICE_EC_OK) {
        std::cout << "Connection event called back with error: " << err << std::endl;
        nabto_device_listener_free(tt->connectionEventListener_);
        return;
    } else {
        if (tt->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_OPENED) {
            std::cout << "New connection opened with reference: " << tt->connectionRef_ << std::endl;
        } else if (tt->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CLOSED) {
            std::cout << "Connection with reference: " << tt->connectionRef_ << " was closed" << std::endl;
        } else if (tt->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED) {
            std::cout << "Connection with reference: " << tt->connectionRef_ << " changed channel" << std::endl;
        } else {
            std::cout << "Unknown connection event: " << tt->connectionEvent_ << " on connection reference: " << tt->connectionRef_ << std::endl;
        }
    }
    tt->startWaitEvent();

}

void TcpTunnel::listenForConnectionEvents()
{
    connectionEventListener_ = nabto_device_connection_events_listener_new(device_);
    if (connectionEventListener_ == NULL) {
        std::cerr << "Failed to listen to connection events" << std::endl;
        return;
    }
    startWaitEvent();
}

void TcpTunnel::startWaitDevEvent()
{
    NabtoDeviceFuture* future;
    // todo consider dynamical resource
    NabtoDeviceError ec = nabto_device_listener_device_event(deviceEventListener_, &future, &deviceEvent_);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to create device event future with ec: " << nabto_device_error_get_message(ec) << std::endl;
        nabto_device_listener_free(deviceEventListener_);
        deviceEventListener_ = NULL;
        return;
    }
    ec = nabto_device_future_set_callback(future, &TcpTunnel::deviceEvent, this);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to set future callback with ec: " << ec << std::endl;
        nabto_device_future_free(future);
        nabto_device_listener_free(deviceEventListener_);
        deviceEventListener_ = NULL;
        return;
    }
}

void TcpTunnel::deviceEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    TcpTunnel* tt = (TcpTunnel*)userData;
    nabto_device_future_free(fut);
    if (err != NABTO_DEVICE_EC_OK) {
        std::cout << "Device event called back with error: " << err << std::endl;
        nabto_device_listener_free(tt->deviceEventListener_);
        return;
    } else {
        if (tt->deviceEvent_ == NABTO_DEVICE_EVENT_ATTACHED) {
            std::cout << "Device is now attached" << std::endl;
        } else if (tt->deviceEvent_ == NABTO_DEVICE_EVENT_DETACHED) {
            std::cout << "Device is now detached" << std::endl;
        } else if (tt->deviceEvent_ == NABTO_DEVICE_EVENT_FAILURE) {
            std::cout << "Device is now in a failure state!" << std::endl;
        } else {
            std::cout << "Unknown device event: " << tt->deviceEvent_ << std::endl;
        }
    }
    tt->startWaitDevEvent();

}

void TcpTunnel::listenForDeviceEvents()
{
    deviceEventListener_ = nabto_device_device_events_listener_new(device_);
    if (deviceEventListener_ == NULL) {
        std::cerr << "Failed to listen to device events" << std::endl;
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
