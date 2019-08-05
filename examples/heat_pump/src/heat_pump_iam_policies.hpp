#ifndef _HEAT_PUMP_IAM_POLICIES_HPP_
#define _HEAT_PUMP_IAM_POLICIES_HPP_

#include <nlohmann/json.hpp>

using json = nlohmann::json;

const json HeatPumpRead = R"(
{
  "Version": 1,
  "Statements": [
    {
      "Allow": true,
      "Actions": ["HeatPump:Get"]
    }
  ]
}
)"_json;

const json HeatPumpWrite = R"(
{
  "Version": 1,
  "Statements": [
    {
      "Allow": true,
      "Actions": [ "HeatPump:Set" ]
    }
  ]
})"_json;

const json IAMFullAccess = R"(
{
  "Version": 1,
  "Name": "IAMFullAccess",
  "Statements": [
    {
      "Actions": [ "IAM:AddUser", "IAM:GetUser", "IAM:ListUsers", "IAM:AddRoleToUser", "IAM:RemoveRoleFromUser" ],
      "Allow": true
    }
  ]
})"_json;

const json ModifyOwnUser = R"(
{
  "Version": 1,
  "Name": "ModifyOwnUser",
  "Statements": [
    {
      "Allow": true,
      "Actions": [ "IAM:AddFingerprint", "IAM:RemoveFingerprint", "IAM:SetName" ],
      "Conditions": [ { "StringEqual": { "Connection:UserId": { "Attribute": "IAM:UserId" } } } ]
    }
  ]
})"_json;

const json FirstUserCanPair = R"(
{
  "Version": 1,
  "Name": "FirstUserCanPair",
  "Statements": [
    {
      "Allow": true,
      "Actions": [ "Pairing:Button" ],
      "Conditions": [ { "NumberEqual": { "Pairing:IsPaired": 0 } } ]
    }
  ]
})"_json;

#endif
