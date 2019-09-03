#pragma once

#include <nabto/nabto_device.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class TcpTunnel {
 public:
    TcpTunnel(const std::string& configFile)
        : configFile_(configFile)
    {}
 private:
    static void iamChanged(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForIamChanges();
    void saveConfig();

    NabtoDevice* device_;
    json config_;
    const std::string& configFile_;
    bool pairing_ = false;
    uint64_t currentIamVersion_;
};
