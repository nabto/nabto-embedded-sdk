## Heatpump example application

This is an example application showing how a heat pump application can be made.

## Howto use

The first time the heatpump application is started it needs to be
started with --init this will write the configuration and state to a
file. Later the application can be started by just providing the
configuration and state file.

// first time the application needs to be initialized and write a config file.
./heatpump --config file.json --init --product-id=... --device-id=... --server=...

// next time is is sufficient to use the configuration file
./heatpump --config file.json

config file structure

{
    "iam": {
        "users": "...",
        "roles": "...",
        "policies": "...",
        "defaultUser": "..."
    },
    "PrivateKey":
}

## Features

The heatpump example shows how a heatpump can be implemented including
iam and heatpump functionality.

## Heatpump Features

This is a hypothetical heatpump. It has the following functionality.

Settings:

The heatpump has four modes:

  * Cool
  * Heat
  * Circulate
  * Dehumidify

The heatpump has two power modes:

  * On
  * Off

A target temperature:

  * TargetTemperature

Sensors:

  * RoomTemperature

### Iam identifiers

Actions:
  * HeatPump:Get get the heatpump state
  * HeatPump:Set set the heatpump state

## Pairing

### A demo running on a pc: (Button)

When the first user, which becomes the owner of the heat pump connects
to the heat pump, it's neccessary to accept the user on the heatpump
within a minute. Else the pairing attempt will fail. If the
fingerprint on the heatpump matches that of the client which wants to
connect the connection can be trusted. Further only a single pairing
can happen at a time, so if the app waits for a pairing and the device
fingerprint was validatet then it's given that the fingerprint matches
the client fingerprint.


### A demo running on a WiFi module. (Button)

The heat pump starts in AP mode. The nabto client connects to the heat
pump, it makes a pairing with the heat pump in AP mode, the client
checks the fingerprint of the heat pump to ensure the connection is
safe. The client initiates the pairing and waits for a button to be
pressed on the device. If another client connects at the same time and
also asks for pairing at the same time, one of the requests will fail,
this way concurrency attacks can be avoided.

### Using a password

If the fingerprint of the heat pump is validated in the client, the
client can assume the connection is secure. In this case a password
can be sent in clear text to prove that the user is allowed to pair
with the device.

If the fingerprint of the heat pump is not validated, it's not safe to
send any confidential information on the connection. Since there could
be a man in the middle attack.

If the heat pump has an access point, the access point can be secured
with a password. In this case anyone connecting can be allowed to pair
with the heat pump.

### Without password or button

It's not generally a good idea to have devices a on network which is
open for anyone become administrator of. A button requires the person
to have physical access to the device. In this case access can also
often be obtained by doing a factory reset of the device. A password
requires the person wanting access to know some secret.



### WIP IAM 2.0
IAM configuration

Users can pair with the device, it requires either a pairing password
or a press on a button on the device.

Roles:

Unknown,
Admin,
guest.

If a user is locally with the heatpump, the app can scan for the
heatpump and the user can pair with the heatpump using a button press
on the heatpump.

If a user is remote from the heatpump, the app can use the passowrd
pairing approach.

### Invite a user to the heatpump.

    1. Create a new pairing token
    3. create a pairing link and send it to the person which is invited.
    4. The user password pairs with the heatpump providing a password and a username.

This needs an attribute on the newly created user which is a pairing password.

${user.PairingPassword}

### Pair with a local heatpump.

    1. Scan and connect to the heatpump locally.
    2. Use button pairing and wait for a press on a button before allowing the new connection.

If this is the first user the user gets admin rights. If this is not
the first user the user gets the role as guest.

### Remote pair with a heatpump.

    1. Use the pairing token provided by the heatpump.
    2. Password pair with the heatpump, without specifying a username.

This could use a password which us stored in the environment for the iam system.

${env.PairingPassword}

### Storage

The heatpump iam policies and roles is static and should be stored statically inside the system.

The users is stored dynamically in a file as e.g. json.
