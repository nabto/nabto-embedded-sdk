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
  "Version": 1,
  "Name": "FullUserAdmin",
  "Statement": [
    {
      "Action": [ "iam:AddUser", "iam:GetUser", "iam:ListUsers", "iam:AddRoleToUser", "iam:RemoveRoleFromUser" ],
      "Allow": true
    }
  ]
})"_json;

const json ModifyOwnUser = R"(
{
  "Version": 1,
  "Name": "ModifyOwnUser",
  "Statement": [
    {
      "Allow": true,
      "Action": [ "iam:AddFingerprint", "iam:RemoveFingerprint", "iam:SetName" ],
      "Condition": [ { "StringEqual": [ { "Attribute": "connection:UserId" }, { "Attribute": "iam:UserId" } ] } ]
    }
  ]
})"_json;

const json FirstUserCanPair = R"(
{
  "Version": 1,
  "Name": "FirstUserCanPair",
  "Statement": [
    {
      "Allow": true,
      "Action": [ "pairing:PairUser" ],
      "Condition": [ { "NumberEqual": [ { "Attribute": "pairing:SystemIsPaired"}, 0 ] } ]
    }
  ]
})"_json;

#endif
