#include "heat_pump.hpp"
#include "json_config.hpp"

#include "heat_pump_set_power.hpp"
#include "heat_pump_set_target.hpp"
#include "heat_pump_set_mode.hpp"
#include "heat_pump_get.hpp"

#include <apps/common/logging.h>
#include <apps/common/json_config.h>
#include <examples/common/stdout_connection_event_handler.hpp>
#include <examples/common/stdout_device_event_handler.hpp>

#include <modules/iam/nm_iam_to_json.h>
#include <modules/iam/nm_iam_from_json.h>
#include <modules/iam/nm_iam_role.h>
#include <modules/policies/nm_statement.h>
#include <modules/policies/nm_policy.h>

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

HeatPump::HeatPump(NabtoDevice* device, nabto::examples::common::DeviceConfig& dc, const std::string& stateFile)
    : device_(device), dc_(dc), stateFile_(stateFile)
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

    pairingPassword_ = nabto::examples::common::random_string(20);
    pairingServerConnectToken_ = nabto::examples::common::random_string(20);

    loadIamPolicy();
    loadState();

    nm_iam_enable_password_pairing(&iam_, pairingPassword_.c_str());

    nm_iam_enable_remote_pairing(&iam_, pairingServerConnectToken_.c_str());

    initCoapHandlers();

    nm_iam_set_user_changed_callback(&iam_, &HeatPump::iamUserChanged, this);

    stdoutConnectionEventHandler_ = nabto::examples::common::StdoutConnectionEventHandler::create(device_);
    stdoutDeviceEventHandler_ = nabto::examples::common::StdoutDeviceEventHandler::create(device_);
    return true;

}

void HeatPump::iamUserChanged(struct nm_iam* iam, const char* userId, void* userData)
{
    HeatPump* hp = static_cast<HeatPump*>(userData);
    hp->userChanged();
}

void HeatPump::userChanged()
{
    saveState();
}

void HeatPump::saveState()
{
    cJSON* state = cJSON_CreateObject();
    cJSON_AddItemToObject(state, "PairingPassword", cJSON_CreateString(pairingPassword_.c_str()));
    cJSON_AddItemToObject(state, "PairingServerConnectToken", cJSON_CreateString(pairingServerConnectToken_.c_str()));

    cJSON* heatPump = cJSON_CreateObject();
    cJSON_AddItemToObject(heatPump, "Mode", cJSON_CreateString(mode_.c_str()));
    cJSON_AddItemToObject(heatPump, "Power", cJSON_CreateBool(power_));
    cJSON_AddItemToObject(heatPump, "Target", cJSON_CreateNumber(target_));

    cJSON_AddItemToObject(state, "HeatPump", heatPump);

    struct nn_string_set userIds;
    nn_string_set_init(&userIds);
    if (!nm_iam_get_users(&iam_, &userIds)) {
        NN_LOG_ERROR(&logger_, LOGM, "Cannot get users from iam module");
    }


    cJSON* usersArray = cJSON_CreateArray();
    const char* str;
    NN_STRING_SET_FOREACH(str, &userIds) {
        struct nm_iam_user* user = nm_iam_find_user(&iam_, str);
        cJSON* encodedUser = nm_iam_user_to_json(user);
        cJSON_AddItemToArray(usersArray, encodedUser);
    }
    cJSON_AddItemToObject(state, "Users", usersArray);

    json_config_save(stateFile_.c_str(), state);

    cJSON_Delete(state);
}

void HeatPump::loadState()
{
    if (!json_config_exists(stateFile_.c_str())) {
        createState();
    }
    cJSON* json;
    if (!json_config_load(stateFile_.c_str(), &json, &logger_)) {
        // log error
        return;
    }

    cJSON* pairingPassword = cJSON_GetObjectItem(json, "PairingPassword");
    cJSON* pairingServerConnectToken = cJSON_GetObjectItem(json, "PairingServerConnectToken");
    cJSON* heatPump = cJSON_GetObjectItem(json, "HeatPump");
    if (cJSON_IsString(pairingPassword)) {
        pairingPassword_ = std::string(pairingPassword->valuestring);
    }
    if (cJSON_IsString(pairingServerConnectToken)) {
        pairingServerConnectToken_ = std::string(pairingServerConnectToken->valuestring);
    }
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

    cJSON* users = cJSON_GetObjectItem(json, "Users");
    if (cJSON_IsArray(users)) {

        size_t usersSize = cJSON_GetArraySize(users);
        for (size_t i = 0; i < usersSize; i++) {
            cJSON* item = cJSON_GetArrayItem(users, i);
            struct nm_iam_user* user = nm_iam_user_from_json(item);
            if (user != NULL) {
                nm_iam_add_user(&iam_, user);
            }
        }
    }
    cJSON_Delete(json);

}
void HeatPump::createState()
{
    // the heatpump starts with the default state so it can just be
    // saved to create a persisted default state.
    saveState();
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
    nabto_device_get_device_fingerprint_full_hex(device_, &fpTemp);
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
    std::cout << "# Product ID:                 " << dc_.getProductId() << std::endl;
    std::cout << "# Device ID:                  " << dc_.getDeviceId() << std::endl;
    std::cout << "# Fingerprint:                " << getFingerprint() << std::endl;
    std::cout << "# Pairing Password            " << pairingPassword_ << std::endl;
    try {
        std::string server = dc_.getServer();
        std::cout << "# Server:                     " << server << std::endl;
    } catch(...) {} // Ignore missing server
    std::cout << "# Client Server Connect Token " << pairingServerConnectToken_ << std::endl;
    std::cout << "# Version:                    " << nabto_device_version() << std::endl;
    std::cout << "# Pairing String              " << createPairingString() << std::endl;
    std::cout << "######## " << std::endl;
}

void HeatPump::dumpIam()
{
    // TODO
}

void HeatPump::setMode(Mode mode)
{
    mode_ = modeToString(mode);
    saveState();
}
void HeatPump::setTarget(double target)
{
    target_ = target;
    saveState();
}

void HeatPump::setPower(bool power)
{
    power_ = power;
    saveState();
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

void HeatPump::loadIamPolicy()
{
    {
        auto p = nm_policy_new("DeviceInfo");
        auto s = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(s, "Info:Get");
        nm_policy_add_statement(p,s);
        nm_iam_add_policy(&iam_, p);
    }
    {
        auto p = nm_policy_new("Pairing");
        auto s = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(s, "Pairing:Get");
        nm_statement_add_action(s, "Pairing:Password");
        nm_statement_add_action(s, "Pairing:Local");
        nm_policy_add_statement(p,s);
        nm_iam_add_policy(&iam_, p);
    }
    {
        auto p = nm_policy_new("Paired");
        auto s = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(s, "Pairing:Get");
        nm_policy_add_statement(p,s);
        nm_iam_add_policy(&iam_, p);
    }
    {
        auto p = nm_policy_new("HeatPumpRead");
        auto s = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(s, "HeatPump:Get");
        nm_policy_add_statement(p,s);
        nm_iam_add_policy(&iam_, p);
    }
    {
        auto p = nm_policy_new("HeatPumpWrite");
        auto s = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(s, "HeatPump:Set");
        nm_policy_add_statement(p,s);
        nm_iam_add_policy(&iam_, p);
    }
    {
        auto p = nm_policy_new("ManageUsers");
        auto s = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(s, "IAM:ListUsers");
        nm_statement_add_action(s, "IAM:GetUser");
        nm_statement_add_action(s, "IAM:DeleteUser");
        nm_statement_add_action(s, "IAM:AddRoleToUser");
        nm_statement_add_action(s, "IAM:RemoveRoleFromUser");
        nm_statement_add_action(s, "IAM:ListRoles");
        nm_policy_add_statement(p, s);
        nm_iam_add_policy(&iam_, p);
    }

    {
        auto r = nm_iam_role_new("Unpaired");
        nm_iam_role_add_policy(r, "Pairing");
        nm_iam_role_add_policy(r, "DeviceInfo");
        nm_iam_add_role(&iam_,r);
    }
    {
        auto r = nm_iam_role_new("Admin");
        nm_iam_role_add_policy(r, "HeatPumpWrite");
        nm_iam_role_add_policy(r, "HeatPumpRead");
        nm_iam_role_add_policy(r, "Paired");
        nm_iam_role_add_policy(r, "DeviceInfo");
        nm_iam_role_add_policy(r, "ManageUsers");
        nm_iam_add_role(&iam_, r);
    }
    {
        auto r = nm_iam_role_new("User");
        nm_iam_role_add_policy(r, "HeatPumpRead");
        nm_iam_role_add_policy(r, "Paired");
        nm_iam_role_add_policy(r, "DeviceInfo");
        nm_iam_add_role(&iam_, r);
    }

}


} } } // namespace
