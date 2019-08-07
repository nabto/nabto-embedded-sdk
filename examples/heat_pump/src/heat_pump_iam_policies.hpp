#ifndef _HEAT_PUMP_IAM_POLICIES_HPP_
#define _HEAT_PUMP_IAM_POLICIES_HPP_

#include <nlohmann/json.hpp>

using json = nlohmann::json;


const json defaultHeatPumpIam = R"(
{
  "DefaultRole": "Unpaired",
  "Policies": {
    "ButtonPairing": {
      "Statements": [
        {
          "Actions": [
            "Pairing:Button"
          ],
          "Allow": true
        }
      ],
      "Version": 1
    },
    "HeatPumpRead": {
      "Statements": [
        {
          "Actions": [
            "HeatPump:Get"
          ],
          "Allow": true
        }
      ],
      "Version": 1
    },
    "HeatPumpWrite": {
      "Statements": [
        {
          "Actions": [
            "HeatPump:Set"
          ],
          "Allow": true
        }
      ],
      "Version": 1
    },
    "IAMFullAccess": {
      "Name": "IAMFullAccess",
      "Statements": [
        {
          "Actions": [
            "IAM:AddUser",
            "IAM:GetUser",
            "IAM:ListUsers",
            "IAM:AddRoleToUser",
            "IAM:RemoveRoleFromUser"
          ],
          "Allow": true
        }
      ],
      "Version": 1
    },
    "ModifyOwnUser": {
      "Name": "IAMFullAccess",
      "Statements": [
        {
          "Actions": [
            "IAM:GetUser",
            "IAM:ListUsers",
            "IAM:AddFingerprint",
            "IAM:RemoveFingerprint"
          ],
          "Allow": true,
          "Conditions": [
            { "AttributeEqual": { "Connection:UserId": "IAM:UserId" } }
          ]
        }
      ],
      "Version": 1
    }
  },
  "Roles": {
    "Unpaired": [
      "ButtonPairing"
    ],
    "Owner": [
      "HeatPumpWrite",
      "HeatPumpRead",
      "IAMFullAccess"
    ],
    "User": [
      "HeatPumpRead",
      "HeatPumpWrite",
      "ModifyOwnUser"
    ],
    "Guest": [
      "HeatPumpRead"
    ]
  },
  "Users": {
  }
}
)"_json;

#endif
