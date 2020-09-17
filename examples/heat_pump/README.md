## Heatpump example application

This is an example application showing how a heat pump application can be made.

## Usage

The demo needs a configuration file, the default configuration file is
named device.json the structure of that file is this:

```json
{
  "ProductId": "...",
  "DeviceId": "..."
}
```

## Configuration files

### `device_config.json`

The configuration of the device. This config is static and never
changes during the lifetime of a device.

### `heat_pump_state.json`

The dynamic runtime state which is updated when the device is running

### `<product_id>_<device_id>.key.json`

The private key used by the device. This file is generated the first
time the device starts and stays static throughout the lifetime of the
device.

## Features

The heatpump example shows how a heatpump can be implemented including
using our fingerprint based Identity and Access Management (IAM) module.

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
can be sent over the connection to prove that the user is allowed to
pair with the device.

If the fingerprint of the heat pump is not validated, it's not safe to
send any confidential information on the connection. Since there could
be a man in the middle attack.

If the heat pump has an access point, the access point can be secured
with a password. In this case anyone connecting can be allowed to pair
with the heat pump.


### Pair with a local heatpump.

    1. Scan and connect to the heatpump locally.
    2. Use button pairing and wait for a press on a button before allowing the new connection.

If this is the first user the user gets the role `admin`. If this is not
the first user the user gets the role as `user`.
