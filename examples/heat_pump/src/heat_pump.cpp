#include "heat_pump.hpp"
#include "json_config.hpp"

#include "heat_pump_set_power.hpp"
#include "heat_pump_set_target.hpp"
#include "heat_pump_set_mode.hpp"
#include "heat_pump_get.hpp"
#include "heat_pump_state.hpp"

#include <apps/common/logging.h>
#include <apps/common/json_config.h>
#include <apps/common/string_file.h>
#include <examples/common/stdout_connection_event_handler.hpp>
#include <examples/common/stdout_device_event_handler.hpp>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_configuration.h>
#include <modules/iam/nm_iam_state.h>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <examples/common/random_string.hpp>

#include <cjson/cJSON.h>

static const char* LOGM = "heat_pump";

namespace nabto {
namespace examples {
namespace heat_pump {

HeatPump::HeatPump(NabtoDevice* device, nabto::examples::common::DeviceConfig& dc, const std::string& iamStateFile, const std::string& hpStateFile)
    : device_(device), dc_(dc), iamStateFile_(iamStateFile), hpStateFile_(hpStateFile)
{
    logging_init(device_, &logger_, "error");
    nm_iam_init(&iam_, device_, &logger_);
}

HeatPump::~HeatPump()
{
    nabto_device_stop(device_);
    nm_iam_deinit(&iam_);
}


bool HeatPump::init()
{
    if (initDevice() != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (!loadIamPolicy() || !loadHpState() || !loadIamState()) {
        return false;
    }

    nabto_device_mdns_add_txt_item(device_, "fn", "Heat Pump");

    initCoapHandlers();

    nm_iam_set_state_changed_callback(&iam_, &HeatPump::iamUserChanged, this);

    stdoutConnectionEventHandler_ = nabto::examples::common::StdoutConnectionEventHandler::create(device_);
    stdoutDeviceEventHandler_ = nabto::examples::common::StdoutDeviceEventHandler::create(device_);
    return true;

}

void HeatPump::iamUserChanged(struct nm_iam* iam, void* userData)
{
    HeatPump* hp = static_cast<HeatPump*>(userData);
    hp->iamStateChanged();
}

void HeatPump::iamStateChanged()
{
    saveIamState();
}

void HeatPump::saveIamState() 
{
    struct nm_iam_state* state = nm_iam_dump_state(&iam_);
    if (state == NULL) {
        return;
    }
    save_iam_state(iamStateFile_.c_str(), state, &logger_);
    nm_iam_state_free(state);
}

void HeatPump::saveIamState(struct nm_iam_state* state) 
{
    char* str = NULL;
    if (!nm_iam_serializer_state_dump_json(state, &str)) {
    } else if (!string_file_save(iamStateFile_.c_str(), str)) {
    }

    nm_iam_serializer_string_free(str);
}

bool HeatPump::loadIamState() 
{
    bool status = true;
    char* str = NULL;
    if (!string_file_load(iamStateFile_.c_str(), &str)) {
        return false;
    }
    struct nm_iam_state* is = nm_iam_state_new();
    nm_iam_serializer_state_load_json(is, str, &logger_);
    if (!nm_iam_load_state(&iam_, is)) {
        NN_LOG_ERROR(&logger_, LOGM, "Failed to load state into IAM module");
        nm_iam_state_free(is);
        is = NULL;
        status = false;
    }
    free(str);
    return status;
}

void HeatPump::saveHpState()
{
    cJSON* state = cJSON_CreateObject();

    cJSON_AddNumberToObject(state, "Version", 3);

    cJSON* heatPump = cJSON_CreateObject();
    cJSON_AddItemToObject(heatPump, "Mode", cJSON_CreateString(mode_.c_str()));
    cJSON_AddItemToObject(heatPump, "Power", cJSON_CreateBool(power_));
    cJSON_AddItemToObject(heatPump, "Target", cJSON_CreateNumber(target_));

    cJSON_AddItemToObject(state, "HeatPump", heatPump);

    json_config_save(hpStateFile_.c_str(), state);

    cJSON_Delete(state);
}

bool HeatPump::loadHpState()
{
    if (!json_config_exists(hpStateFile_.c_str())) {
        createHpState();
    }
    cJSON* json;
    if (!json_config_load(hpStateFile_.c_str(), &json, &logger_)) {
        NN_LOG_ERROR(&logger_, LOGM, "Cannot load state from file %s", hpStateFile_.c_str());
        return false;
    }

    cJSON* version = cJSON_GetObjectItem(json, "Version");
    if (!cJSON_IsNumber(version) || version->valueint != 2) {
        NN_LOG_ERROR(&logger_, LOGM, "The version of the state file %s is not correct, delete it and start over", hpStateFile_.c_str());
        return false;
    }

    cJSON* heatPump = cJSON_GetObjectItem(json, "HeatPump");

    if (cJSON_IsObject(heatPump)) {
        cJSON* mode = cJSON_GetObjectItem(heatPump, "Mode");
        cJSON* power = cJSON_GetObjectItem(heatPump, "Power");
        cJSON* target = cJSON_GetObjectItem(heatPump, "Target");

        if (cJSON_IsString(mode)) {
            mode_ = std::string(mode->valuestring);
        }

        if (cJSON_IsNumber(target)) {
            target_ = mode->valuedouble;
        }

        if (cJSON_IsBool(power)) {
            if (power->type == cJSON_False) {
                power_ = false;
            } else {
                power_ = true;
            }
        }
    }

    cJSON_Delete(json);
    return true;
}

void HeatPump::createHpState()
{
    // the heatpump starts with the default state so it can just be
    // saved to create a persisted default state.
    saveHpState();
}

void HeatPump::createIamState()
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
    saveIamState(state);
    nm_iam_state_free(state);
}


void HeatPump::initCoapHandlers()
{
    coapSetPower_ = nabto::examples::heat_pump::HeatPumpSetPower::create(*this, device_);
    coapSetTarget_ = nabto::examples::heat_pump::HeatPumpSetTarget::create(*this, device_);
    coapSetMode_ = nabto::examples::heat_pump::HeatPumpSetMode::create(*this, device_);
    coapGet_ = nabto::examples::heat_pump::HeatPumpGet::create(*this, device_);
}

NabtoDeviceError HeatPump::initDevice()
{
    NabtoDeviceError ec;
    ec = nabto_device_set_product_id(device_, dc_.getProductId().c_str());
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_device_id(device_, dc_.getDeviceId().c_str());
    if (ec) {
        return ec;
    }
    try {
        std::string url = dc_.getServer();
        ec = nabto_device_set_server_url(device_, url.c_str());
        std::cout << "serverURL set to: " << url << std::endl;
        if (ec) {
            return ec;
        }
    } catch (...) {
        // Ignore missing server, api will fix
    }

    nabto_device_set_app_name(device_, appName_.c_str());
    nabto_device_set_app_version(device_, appVersion_.c_str());

    ec = nabto_device_enable_mdns(device_);
    if (ec) {
        return ec;
    }

    ec = nabto_device_mdns_add_subtype(device_, "heatpump");
    if (ec) {
        return ec;
    }





    ec = nabto_device_set_log_std_out_callback(device_);
    if (ec) {
        return ec;
    }

    if (!logLevel_.empty()) {
        nabto_device_set_log_level(device_, logLevel_.c_str());
    }

    // run application
    NabtoDeviceFuture* fut = nabto_device_future_new(device_);
    nabto_device_start(device_, fut);

    ec = nabto_device_future_wait(fut);
    nabto_device_future_free(fut);

    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to start device" << std::endl;
        return ec;
    }
    return NABTO_DEVICE_EC_OK;
}

void HeatPump::setLogLevel(const std::string& logLevel)
{
    logLevel_ = logLevel;
}

std::string HeatPump::getFingerprint()
{
    char* fpTemp;
    nabto_device_get_device_fingerprint(device_, &fpTemp);
    std::string fp(fpTemp);
    nabto_device_string_free(fpTemp);
    return fp;
}

std::string HeatPump::createPairingString()
{
    std::stringstream ss;
    ss << "p=" << dc_.getProductId()
       << ",d=" << dc_.getDeviceId()
       << ",pwd=" << pairingPassword_
       << ",sct=" << pairingServerConnectToken_;
    return ss.str();
}

void HeatPump::printHeatpumpInfo()
{
    std::cout << "######## Nabto heat pump device ########" << std::endl;
    std::cout << "# Product ID:                  " << dc_.getProductId() << std::endl;
    std::cout << "# Device ID:                   " << dc_.getDeviceId() << std::endl;
    std::cout << "# Fingerprint:                 " << getFingerprint() << std::endl;
    std::cout << "# Pairing Password:            " << pairingPassword_ << std::endl;
    std::cout << "# Pairing Server Connect Token:" << pairingServerConnectToken_ << std::endl;
    try {
        std::string server = dc_.getServer();
        std::cout << "# Server:                      " << server << std::endl;
    } catch(...) {} // Ignore missing server
    std::cout << "# Version:                     " << nabto_device_version() << std::endl;
    std::cout << "# Pairing String               " << createPairingString() << std::endl;
    std::cout << "######## " << std::endl;
}

void HeatPump::dumpIam()
{
    // TODO
}

void HeatPump::setMode(Mode mode)
{
    mode_ = modeToString(mode);
    saveHpState();
}
void HeatPump::setTarget(double target)
{
    target_ = target;
    saveHpState();
}

void HeatPump::setPower(bool power)
{
    power_ = power;
    saveHpState();
}

const char* HeatPump::modeToString(HeatPump::Mode mode)
{
    switch (mode) {
        case HeatPump::Mode::COOL: return "COOL";
        case HeatPump::Mode::HEAT: return "HEAT";
        case HeatPump::Mode::FAN: return "FAN";
        case HeatPump::Mode::DRY: return "DRY";
        default: return "UNKNOWN";
    }
}

bool HeatPump::checkAccess(NabtoDeviceCoapRequest* request, const std::string& action)
{
    if (!nm_iam_check_access(&iam_, nabto_device_coap_request_get_connection_ref(request), action.c_str(), NULL)) {
        nabto_device_coap_error_response(request, 403, "Unauthorized");
        nabto_device_coap_request_free(request);
        return false;
    }
    return true;
}

bool HeatPump::loadIamPolicy()
{
    struct nm_iam_configuration* conf = nm_iam_configuration_new();
    {
        auto p = nm_iam_configuration_policy_new("Pairing");
        auto s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "Pairing:Get");
        nm_iam_configuration_statement_add_action(s, "Pairing:PasswordOpen");
        nm_iam_configuration_statement_add_action(s, "Pairing:PasswordInvite");
        nm_iam_configuration_statement_add_action(s, "Pairing:LocalInitial");
        nm_iam_configuration_statement_add_action(s, "Pairing:LocalOpen");
        nm_iam_configuration_add_policy(conf, p);
    }
    {
        auto p = nm_iam_configuration_policy_new("HeatPumpControl");
        auto s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "HeatPump:Get");
        nm_iam_configuration_statement_add_action(s, "HeatPump:Set");
        nm_iam_configuration_add_policy(conf, p);
    }
    {
        auto p = nm_iam_configuration_policy_new("ManageIam");
        auto s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "IAM:ListUsers");
        nm_iam_configuration_statement_add_action(s, "IAM:GetUser");
        nm_iam_configuration_statement_add_action(s, "IAM:DeleteUser");
        nm_iam_configuration_statement_add_action(s, "IAM:SetUserRole");
        nm_iam_configuration_statement_add_action(s, "IAM:ListRoles");
        nm_iam_configuration_statement_add_action(s, "IAM:SetSettings");
        nm_iam_configuration_statement_add_action(s, "IAM:GetSettings");
        
        nm_iam_configuration_add_policy(conf, p);
    }

    {
        auto p = nm_iam_configuration_policy_new("ManageOwnUser");
        {
            auto s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
            nm_iam_configuration_statement_add_action(s, "IAM:GetUser");
            nm_iam_configuration_statement_add_action(s, "IAM:DeleteUser");
            nm_iam_configuration_statement_add_action(s, "IAM:SetDisplayName");

            // Create a condition such that only connections where the
            // UserId matches the UserId of the operation is allowed. E.g. IAM:Username == ${Connection:Username}

            auto c = nm_iam_configuration_statement_create_condition(s, NM_IAM_CONDITION_OPERATOR_STRING_EQUALS, "IAM:Username");
            nm_iam_configuration_condition_add_value(c, "${Connection:Username}");
        }
        {
            auto s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
            nm_iam_configuration_statement_add_action(s, "IAM:ListUsers");
            nm_iam_configuration_statement_add_action(s, "IAM:ListRoles");
        }

        nm_iam_configuration_add_policy(conf, p);
    }

    {
        auto r = nm_iam_configuration_role_new("Unpaired");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(conf,r);
    }
    {
        auto r = nm_iam_configuration_role_new("Administrator");
        nm_iam_configuration_role_add_policy(r, "ManageIam");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "HeatPumpControl");
        nm_iam_configuration_add_role(conf, r);
    }
    {
        auto r = nm_iam_configuration_role_new("Standard");
        nm_iam_configuration_role_add_policy(r, "HeatPumpControl");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_add_role(conf, r);
    }
    {
        //TODO: guest should have access to LocalHeatpumpControl and LocalDeviceInfo
        auto r = nm_iam_configuration_role_new("Guest");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(conf, r);

    }

    // Connections which does not have a paired user in the system gets the Unpaired role.
    nm_iam_configuration_set_unpaired_role(conf, "Unpaired");

    return nm_iam_load_configuration(&iam_, conf);
}


} } } // namespace
