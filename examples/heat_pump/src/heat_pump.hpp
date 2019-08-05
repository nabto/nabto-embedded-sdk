#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <nlohmann/json.hpp>

#include <mutex>
#include <thread>

static const char* OWNER_USER_NAME = "owner";

using json = nlohmann::json;

class HeatPump {
  public:

    HeatPump(NabtoDevice* device, const std::string& configFile)
        : device_(device), configFile_(configFile)
    {
    }

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

    Mode getMode();
    const char* modeToString(Mode mode);
    const char* getModeString();
    double getTarget();
    bool getPower();
    double getTemperature();

    bool saveConfig();
    bool loadConfig();

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

    NabtoDeviceError isPaired(bool& isPaired) {
        std::vector<uint8_t> cbor(1024);
        size_t used;

        NabtoDeviceError ec = nabto_device_iam_users_get(device_, OWNER_USER_NAME, cbor.data(), cbor.size(), &used);
        if (ec) {
            return ec;
        }
        cbor.resize(used);

        json user = json::from_cbor(cbor);
        isPaired = (user["Fingerprints"].size() != 0);
        return NABTO_DEVICE_EC_OK;
    }

    std::unique_ptr<std::thread> pairingThread_;
  private:
    std::mutex mutex_;
    NabtoDevice* device_;
    const std::string& configFile_;
    json state_;
    bool pairing_ = false;
};

#endif
