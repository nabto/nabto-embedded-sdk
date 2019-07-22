#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include <nabto/nabto_device.h>

#include <nlohmann/json.hpp>

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

  private:
    NabtoDevice* device_;
    const std::string& configFile_;
    json state_;
};

#endif
