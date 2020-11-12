#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include "heat_pump_state.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>



#include <modules/iam/nm_iam.h>

#include <examples/common/device_config.hpp>

#include <nlohmann/json.hpp>

#include <nn/log.h>

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

class HeatPumpSetName;
class HeatPumpSetPower;
class HeatPumpSetTarget;
class HeatPumpSetMode;
class HeatPumpGet;

class HeatPump {
  public:

    HeatPump(NabtoDevice* device, nabto::examples::common::DeviceConfig& dc, const std::string& iamStateFile, const std::string& hpStateFile);

    ~HeatPump();

    bool init();

    void printHeatpumpInfo();
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
    void setName(const std::string& name);
    const char* modeToString(HeatPump::Mode mode);
    const char* getModeString();


    nlohmann::json getState()
    {
        nlohmann::json state;
        state["Mode"] = state_.mode_;
        state["Target"] = state_.target_;
        state["Power"] = state_.power_;
        state["Temperature"] = 22.3;
        return state;
    }

    bool checkAccess(NabtoDeviceCoapRequest* request, const std::string& action);

    bool loadIamPolicy();

 private:

    static void iamUserChanged(struct nm_iam* iam, void* userData);
    void iamStateChanged();
    void hpStateChanged();

    void saveIamState();
    void saveIamState(struct nm_iam_state* state);
    bool loadIamState();
    void createIamState();
    
    void saveHpState();
    bool loadHpState();
    void createHpState();

    void initCoapHandlers();
    std::string getFingerprint();
    std::string createPairingString();

    NabtoDevice* device_;
    nabto::examples::common::DeviceConfig& dc_;

    struct nn_log logger_;
    std::string logLevel_;
    struct nm_iam iam_;

    std::unique_ptr<HeatPumpSetPower> coapSetPower_;
    std::unique_ptr<HeatPumpSetTarget> coapSetTarget_;
    std::unique_ptr<HeatPumpSetMode> coapSetMode_;
    std::unique_ptr<HeatPumpGet> coapGet_;

    std::unique_ptr<nabto::examples::common::StdoutConnectionEventHandler> stdoutConnectionEventHandler_;
    std::unique_ptr<nabto::examples::common::StdoutDeviceEventHandler> stdoutDeviceEventHandler_;

    std::string appName_ = "HeatPump";
    std::string appVersion_ = "1.0.0";

    std::string iamStateFile_;
    std::string hpStateFile_;

    HeatPumpState state_;

    std::string pairingPassword_;
    std::string pairingServerConnectToken_;
};

} } } // namespace

#endif
