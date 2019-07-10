## Api considerations.

  * be able to come with custom actions.
  * be able to come with custom attributes.
  * be able to control roles for a connection.

api:
  * `check_action(environment, action);`
  * `associate_role_with_connection(connection, role);`

  * `add_role(device, role)`
  * `remove_role(device, role)`
  * `list_roles(device)`
  * `add_policy(device, policy)`
  * `remove_policy(device, policy)`
  * `add_user(device, user)`
  * `remove_user(device, user)`
  * `list_users(device)`


Alternative 1:

Let iam live inside the core
/**
 * Modify iam system
 */
nabto_device_iam_add_user(NabtoDevice* device, ...)
nabto_device_iam_remove_user(NabtoDevice* device, ...)

Alternative 2:

Let iam live outside the core, and have callbacks for certain events.

nabto_device_connection_created_cb(connection* )
nabto_device_connection_destroyed_cb(connection* )
nabto_device_coap_request_cb()
Call out from the core on certain events


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
      "defaultUser": "Anonymous"
    }
}
```
