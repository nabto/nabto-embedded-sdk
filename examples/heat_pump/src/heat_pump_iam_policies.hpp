#ifndef _HEAT_PUMP_IAM_POLICIES_HPP_
#define _HEAT_PUMP_IAM_POLICIES_HPP_

#include <nlohmann/json.hpp>

using json = nlohmann::json;


const json defaultHeatPumpIam = R"(
{
  "DefaultUser": "Unpaired",
  "Policies": {
    "FirstUserCanPair": {
      "Name": "FirstUserCanPair",
      "Statements": [
        {
          "Actions": [
            "Pairing:Button"
          ],
          "Allow": true,
          "Conditions": [
            { "NumberEqual": { "Pairing:IsPaired": 0 } }
          ]
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
            { "StringEqual": { "Connection:UserId": { "Attribute": "IAM:UserId" } } }
          ]
        }
      ],
      "Version": 1
    },
    "ButtonPairAsGuest": {
      "Version": 1,
      "Statements": [
        {
          "Allow": true,
          "Actions": [ "Pairing:ButtonGuest" ]
        }
      ]
    }
  },
  "Roles": {
    "Unpaired": [
      "FirstUserCanPair",
      "ButtonPairAsGuest"
    ],
    "FullAccess": [
      "HeatPumpWrite",
      "HeatPumpRead",
      "IAMFullAccess"
    ],
    "GuestAccess": [
      "HeatPumpRead",
      "HeatPumpWrite",
      "ModifyOwnUser"
    ]
  },
  "Users": {
    "Unpaired": {
      "Fingerprints": [],
      "Roles": [
        "Unpaired"
      ]
    },
    "owner": {
      "Fingerprints": [
      ],
      "Roles": [
        "FullAccess"
      ]
    }
  }
}
)"_json;

#endif
