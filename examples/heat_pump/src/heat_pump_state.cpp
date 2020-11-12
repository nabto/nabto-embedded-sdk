
#include <apps/common/string_file.h>
#include <examples/common/random_string.hpp>
#include <apps/common/json_config.h>


#include "heat_pump_state.hpp"


#include <modules/iam/nm_iam_serializer.h>

#include <cjson/cJSON.h>


namespace nabto {
namespace examples {
namespace heat_pump {

void save_iam_state(const char* filename, struct nm_iam_state* state, struct nn_log* logger)
{
    char* str = NULL;
    if (!nm_iam_serializer_state_dump_json(state, &str)) {
    } else if (!string_file_save(filename, str)) {
    }
    nm_iam_serializer_string_free(str);
}
void save_heat_pump_state(const char* filename, const HeatPumpState& state)
{
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "Version", 3);

    cJSON* heatPump = cJSON_CreateObject();
    cJSON_AddItemToObject(heatPump, "Mode", cJSON_CreateString(state.mode_.c_str()));
    cJSON_AddItemToObject(heatPump, "Power", cJSON_CreateBool(state.power_));
    cJSON_AddItemToObject(heatPump, "Target", cJSON_CreateNumber(state.target_));

    cJSON_AddItemToObject(root, "HeatPump", heatPump);

    json_config_save(filename, root);

    cJSON_Delete(root);
}

void create_default_iam_state(const char* filename)
{
    struct nm_iam_state* state = nm_iam_state_new();
    struct nm_iam_user* user = nm_iam_state_user_new("admin");
    std::string sct = nabto::examples::common::random_string(12);
    nm_iam_state_user_set_sct(user, sct.c_str());
    nm_iam_state_user_set_role(user, "Administrator");
    nm_iam_state_add_user(state, user);
    nm_iam_state_set_initial_pairing_username(state, "admin");
    nm_iam_state_set_local_initial_pairing(state, true);
    nm_iam_state_set_local_open_pairing(state, true);
    nm_iam_state_set_open_pairing_role(state, "Guest");
    save_iam_state(filename, state, NULL);
    nm_iam_state_free(state);
}
void create_default_heat_pump_state(const char* filename)
{
    HeatPumpState state;
    save_heat_pump_state(filename, state);
}

} } }
