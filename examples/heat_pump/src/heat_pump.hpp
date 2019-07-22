#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include <nlohmann/json.hpp>

using json = nlohmann::json;

class HeatPump {
  public:
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



  private:
    json state_;
};

#endif
