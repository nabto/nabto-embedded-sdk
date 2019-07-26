#ifndef _HEAT_PUMP_IAM_POLICIES_HPP_
#define _HEAT_PUMP_IAM_POLICIES_HPP_

#include <nlohmann/json.hpp>

using json = nlohmann::json;

const json Heat_PumpRead = R"(
{
  "Version": 1,
  "Statement": [
    {
      "Allow": true,
      "Action": ["HeatPump:Get"]
    }
  ]
}
)"_json;

const json Heat_PumpWrite = R"(
{
  "Version": 1,
  "Statement": [
    {
      "Allow": true,
      "Action": [ "HeatPump:Set" ]
    }
  ]
})"_json;

const json FullUserAdmin = R"(
{
  "Version": 1,
  "Name": "FullUserAdmin",
  "Statement": [
    {
      "Action": [ "IAM:AddUser", "IAM:GetUser", "IAM:ListUsers", "IAM:AddRoleToUser", "IAM:RemoveRoleFromUser" ],
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
      "Action": [ "IAM:AddFingerprint", "IAM:RemoveFingerprint", "IAM:SetName" ],
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
