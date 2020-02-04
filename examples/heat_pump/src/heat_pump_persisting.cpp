#include "heat_pump_persisting.hpp"
#include "json_config.hpp"

#include <modules/iam_cpp/iam.hpp>
#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>
#include <modules/iam_cpp/iam_builder.hpp>

namespace nabto {

HeatPumpPersisting::HeatPumpPersisting(const std::string& configFile)
    : configFile_(configFile)
{

}

bool HeatPumpPersisting::loadUsersIntoIAM()
{
    // if (!json_config_load(configFile_, config_)) {
    //     return false;
    // }

    // auto users = config_["Users"];

    // std::vector<iam::User> us;
    // iam::IAMToJson::usersFromJson(users, us);

    // return true;
}

void HeatPumpPersisting::upsertUser(const User& user)
{
    // TODO
    //config_["Users"][user.getName()] = nabto::iam::IAMToJson::userToJson(user);
    save();
}

void HeatPumpPersisting::deleteUser(const std::string& userId)
{
    config_["Users"].erase(userId);
    save();
}

void HeatPumpPersisting::save()
{
    json_config_save(configFile_, config_);
}


} // namespace
