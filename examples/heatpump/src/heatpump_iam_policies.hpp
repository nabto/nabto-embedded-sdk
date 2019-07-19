#ifndef _HEATPUMP_IAM_POLICIES_HPP_
#define _HEATPUMP_IAM_POLICIES_HPP_

#include <nlohmann/json.hpp>

using json = nlohmann::json;

const json HeatPumpRead = R"(
{
  "Version": 1,
  "Statement": [
    {
      "Allow": true,
      "Action": ["heatpump:GetTargetTemperature", "heatpump:GetTemperature", "heatpump:GetMode"]
    }
  ]
}
)"_json;

const json HeatPumpWrite = R"(
{
  "Version": 1,
  "Statement": [
    {
      "Allow": true,
      "Action": [ "heatpump:SetTargetTemperature", "heatpump:SetTemperature", "heatpump:SetMode" ]
    }
  ]
})"_json;

const json FullUserAdmin = R"(
{
  "version": 1,
  "name": "FullUserAdmin",
  "statements": [
    {
      "actions": [ "iam:AddUser", "iam:GetUser", "iam:ListUsers", "iam:AddRoleToUser", "iam:RemoveRoleFromUser" ],
      "effect": "Allow"
    }
  ]
})"_json;

const json ModifyOwnUser = R"(
{
  "version": 1,
  "name": "ModifyOwnUser",
  "statements": [
    {
      "effect": "Allow",
      "actions": [ "iam:AddFingerprint", "iam:RemoveFingerprint", "iam:SetName" ],
      "conditions": { "StringEqual": [ { "Attribute": "connection:UserId" }, { "Attribute": "iam:UserId" } ] }
    }
  ]
})"_json;

const json FirstUserCanPair = R"(
{
  "version": 1,
  "name": "FirstUserCanPair",
  "statements": [
    {
      "effect": "Allow",
      "actions": [ "pairing:PairUser" ],
      "conditions": { "NumberEqual": [ { "Attribute": "pairing:SystemIsPaired"}, 0 ] }
    }
  ]
})"_json;

#endif
