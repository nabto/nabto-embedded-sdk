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
