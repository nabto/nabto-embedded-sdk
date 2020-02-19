#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "heat_pump_persisting.hpp"
#include <modules/fingerprint_iam/fingerprint_iam.hpp>

#include <examples/common/device_config.hpp>

#include <nlohmann/json.hpp>

#include <mutex>
#include <thread>
#include <sstream>


using json = nlohmann::json;

namespace nabto {
namespace examples {
namespace common {

class StdoutConnectionEventHandler;
class StdoutDeviceEventHandler;

} } }  // namespace

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpSetPower;
class HeatPumpSetTarget;
class HeatPumpSetMode;
class HeatPumpGet;

class HeatPump {
  public:

    HeatPump(NabtoDevice* device, const std::string& privateKey, nabto::examples::common::DeviceConfig& dc, const std::string& stateFile);

    ~HeatPump();

    bool init();

    void printHeatpumpInfo();
    void dumpIam();
    void setLogLevel(const std::string& logLevel);

    NabtoDeviceError initDevice();

    enum class Mode {
        COOL = 0,
        HEAT = 1,
        FAN = 2,
        DRY = 3,
    };

    NabtoDevice* getDevice()
    {
        return device_;
    }

    void setMode(Mode mode);
    void setTarget(double target);
    void setPower(bool on);
    const char* modeToString(HeatPump::Mode mode);
    const char* getModeString();


    nlohmann::json getState()
    {
        nlohmann::json state;
        state["Mode"] = persisting_->getHeatPumpMode();
        state["Target"] = persisting_->getHeatPumpTarget();
        state["Power"] = persisting_->getHeatPumpPower();
        state["Temperature"] = 22.3;
        return state;
    }

    nlohmann::json getInfo()
    {
        nlohmann::json info;
        std::string nabtoVersion(nabto_device_version());
        info["NabtoVersion"] = nabtoVersion;
        info["AppName"] = appName_;
        info["AppVersion"] = appVersion_;
        return info;
    }

    bool checkAccess(NabtoDeviceCoapRequest* request, const std::string& action);

    void loadIamPolicy();

 private:

    void initCoapHandlers();

    NabtoDevice* device_;
    std::string privateKey_;
    nabto::examples::common::DeviceConfig& dc_;
    std::shared_ptr<HeatPumpPersisting> persisting_;

    fingerprint_iam::FingerprintIAM fingerprintIAM_;

    std::unique_ptr<HeatPumpSetPower> coapSetPower_;
    std::unique_ptr<HeatPumpSetTarget> coapSetTarget_;
    std::unique_ptr<HeatPumpSetMode> coapSetMode_;
    std::unique_ptr<HeatPumpGet> coapGet_;

    std::unique_ptr<nabto::examples::common::StdoutConnectionEventHandler> stdoutConnectionEventHandler_;
    std::unique_ptr<nabto::examples::common::StdoutDeviceEventHandler> stdoutDeviceEventHandler_;

    std::string appName_ = "HeatPump";
    std::string appVersion_ = "1.0.0";

};

} } } // namespace

#endif
