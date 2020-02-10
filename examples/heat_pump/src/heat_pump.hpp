#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "heat_pump_persisting.hpp"
#include <modules/fingerprint_iam/fingerprint_iam.hpp>

#include <nlohmann/json.hpp>

#include <mutex>
#include <thread>
#include <sstream>

using json = nlohmann::json;

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpSetPower;
class HeatPumpSetTarget;
class HeatPumpSetMode;
class HeatPumpGet;
class HeatPumpGetClientSettings;

class HeatPumpConnectionEventHandler;
class HeatPumpDeviceEventHandler;

class HeatPump {
  public:

    HeatPump(NabtoDevice* device, nabto::fingerprint_iam::FingerprintIAM& iam, HeatPumpPersisting& persisting);

    ~HeatPump();

    void init();

    void printHeatpumpInfo();
    void setLogLevel(const std::string& logLevel);

    NabtoDeviceError initDevice();

    void deinit()
    {
    }

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


    json getState()
    {
        nlohmann::json state;
        state["Mode"] = persisting_.getHeatPumpMode();
        state["Target"] = persisting_.getHeatPumpTarget();
        state["Power"] = persisting_.getHeatPumpPower();
        state["Temperature"] = 22.3;
        return state;
    }

    std::string getClientServerUrl()
    {
        return persisting_.getClientServerUrl();
    }

    std::string getClientServerKey()
    {
        return persisting_.getClientServerKey();
    }

    bool checkAccess(NabtoDeviceCoapRequest* request, const std::string& action);


 private:

    void initCoapHandlers();

    NabtoDevice* device_;

    HeatPumpPersisting& persisting_;
    fingerprint_iam::FingerprintIAM& fingerprintIAM_;

    std::unique_ptr<nabto::examples::heat_pump::HeatPumpSetPower> coapSetPower_;
    std::unique_ptr<nabto::examples::heat_pump::HeatPumpSetTarget> coapSetTarget_;
    std::unique_ptr<nabto::examples::heat_pump::HeatPumpSetMode> coapSetMode_;
    std::unique_ptr<nabto::examples::heat_pump::HeatPumpGet> coapGet_;
    std::unique_ptr<nabto::examples::heat_pump::HeatPumpGetClientSettings> coapGetClientSettings_;

    std::unique_ptr<nabto::examples::heat_pump::HeatPumpConnectionEventHandler> heatPumpConnectionEventHandler_;
    std::unique_ptr<nabto::examples::heat_pump::HeatPumpDeviceEventHandler> heatPumpDeviceEventHandler_;


};

} } } // namespace

#endif
