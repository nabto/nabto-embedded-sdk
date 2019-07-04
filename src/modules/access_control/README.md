## conditions grammar


```
Expression := Predicate | { Expression, BooleanOperation, Expression }
BooleanOperation := 'And' | 'Or'
Predicate := Attribute, PredicateOperation, { Attribute | string | number}
PredicateOperation := 'StringEqual', 'NumberEqual'
Attribute := Identifier
```


{
    "And": [ { "NumberEqual": [ { "Attribute": "tunnel:port" }, 42] },
             { "StringEqual": [ { "Attribute": "tunnel:host" }, "localhost"] } ]
}



## Example heatpump access control system

```
{
  "version": 1,
  "name": "HeatpumpRead",
  "statements": [
    {
      "actions": [ "heatpump:GetTargetTemperature", "heatpump:GetTemperature", "heatpump:GetMode" ],
      "effect": "Allow"
    }
  ]
}
```

```
{
  "version": 1,
  "name": "HeatpumpWrite",
  "statements": [
    {
      "actions": [ "heatpump:SetTargetTemperature", "heatpump:SetTemperature", "heatpump:SetMode" ],
      "effect": "Allow"
    }
  ]
}
```

```
{
  "version": 1,
  "name": "FullUserAdmin",
  "statements": [
    {
      "actions": [ "iam:AddUser", "iam:GetUser", "iam:ListUsers", "iam:AddRoleToUser", "iam:RemoveRoleFromUser" ],
      "effect": "Allow"
    }
  ]
}
```

```
{
  "version": 1,
  "name": "ModifyOwnUser",
  "statements": [
    {
      "effect": "Allow",
      "actions": [ "iam:AddFingerprint", "iam:RemoveFingerprint", "iam:SetName" ],
      "conditions": { "StringEqual": [ { "Attribute": "connection:UserId" }, { "Attribute": "iam:UserId" } ]
      }
    }
  ]
}
```

```
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
}
```

```
{
  "version": 1,
  "name": "CanAskForAccess",
  "statements": [
    {
      "effect": "Allow",
      "actions": [ "pairing:AskOwnerForAccess" ]
    }
  ]
}
```

```
{
    "version": 1,
    "roles": [
        {
            "name": "Owner",
            "policies": [ "HeatpumpWrite", "HeatpumpRead", "FullUserAdmin" ]
        },
        {
            "name": "Guest",
            "policies": [ "HeatpumpRead", "IamAddOwnFingerprintToAcl" ]
        },
        {
            "name": "Anonymous",
            "policies": [ "CanAskForAccess", "FirstUserCanPair" ]
        }
    ],
    "users": [
        {
            "name": "user1",
            "roles": [ "Owner" ],
            "fingerprints": [ "11223344556677881122334455667788" ]
        },
        {
            "name": "user2",
            "roles": [ "Guest" ],
            "fingerprints": [ "88776655443322118877665544332211" ]
        },
        {
            "name": "Anonymous",
            "roles": [ "Anonymous" ]
        }
    ],
    "system": {
      "defaultUser": [ "Anonymous" ]
    }
}
```
