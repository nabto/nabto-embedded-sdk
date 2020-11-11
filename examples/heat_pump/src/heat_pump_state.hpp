#pragma once

#include <modules/iam/nm_iam_state.h>
#include <string>


namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpState {
 public:
    bool power_ = false;
    double target_ = 22.3;
    std::string mode_ = "COOL";
};

void save_iam_state(const char* filename, struct nm_iam_state* state, struct nn_log* logger);
void save_heat_pump_state(const char* filename, const HeatPumpState& state);
void create_default_iam_state(const char* filename);
void create_default_heat_pump_state(const char* filename);

} } } // namespace
