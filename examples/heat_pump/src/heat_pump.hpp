#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <nlohmann/json.hpp>

#include <mutex>
#include <thread>
#include <sstream>

static const char* OWNER_USER_NAME = "owner";
static const char* GUEST_ROLE_NAME = "GuestAccess";

using json = nlohmann::json;

class HeatPump {
  public:

    HeatPump(NabtoDevice* device, json config, const std::string& configFile)
        : device_(device), config_(config), configFile_(configFile)
    {
    }

    void init();

    enum class Mode {
        COOL = 0,
        HEAT = 1,
        FAN = 2,
        DRY = 3,

    };

    NabtoDevice* getDevice() {
        return device_;
    }

    void setMode(Mode mode);
    void setTarget(double target);
    void setPower(bool on);
    const char* modeToString(HeatPump::Mode mode);
    const char* getModeString();
    json getState() {
        return config_["HeatPump"];
    }

    bool beginPairing() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (pairing_) {
            return false;
        }
        pairing_ = true;
        return true;
    }
    void pairingEnded() {
        std::unique_lock<std::mutex> lock(mutex_);
        pairing_ = false;
    }

    NabtoDeviceError userCount(size_t& count)
    {
        std::vector<uint8_t> cbor(1024);
        size_t used;

        NabtoDeviceError ec = nabto_device_iam_users_list(device_, cbor.data(), cbor.size(), &used);
        if (ec) {
            return ec;
        }
        cbor.resize(used);

        json users = json::from_cbor(cbor);
        count = users.size();
        return NABTO_DEVICE_EC_OK;
    }

    NabtoDeviceError nextUserName(std::string& name)
    {
        for (int i = 0;; i++) {
            std::stringstream ss;
            ss << "User-" << i;
            auto str = ss.str();
            size_t used;
            NabtoDeviceError ec = nabto_device_iam_users_get(device_, str.c_str(), NULL, 0, &used);
            if (ec == NABTO_DEVICE_EC_OUT_OF_MEMORY) {
                // user was found but buffer was too small
                continue;
            } else if (ec == NABTO_DEVICE_EC_NO_SUCH_RESOURCE) {
                // user was not found use this for the next user
                name = str;
                return NABTO_DEVICE_EC_OK;
            } else {
                return ec;
            }
        }
    }

    std::unique_ptr<std::thread> pairingThread_;
  private:

    static void iamChanged(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForIamChanges();
    void saveConfig();

    std::mutex mutex_;
    NabtoDevice* device_;
    json config_;
    const std::string& configFile_;
    bool pairing_ = false;
    uint64_t currentIamVersion_;

};

#endif
