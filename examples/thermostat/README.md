## Thermostat example application

This is an example application showing how a thermostat application can be made.

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

### `config/device_config.json`

The configuration of the device. This config is static and never
changes during the lifetime of a device.

### `state/thermostat_device_iam_state.json` and `state/thermostat_device_state.json

The dynamic runtime state which is updated when the device is running

### `keys/device.key`

The private key used by the device. This file is generated the first
time the device starts and stays static throughout the lifetime of the
device.

## Features

The thermostat example shows how a thermostat can be implemented including using our fingerprint based
Identity and Access Management (IAM) module. The IAM module supports SCTs, so clients can connect
using server keys of any authentication type.

## Thermostat Features

This is a hypothetical thermostat. It has the following functionality.

Settings:

The thermostat has four modes:

  * Cool
  * Heat
  * Circulate
  * Dehumidify

The thermostat has two power modes:

  * On
  * Off

A target temperature:

  * TargetTemperature

Sensors:

  * RoomTemperature

### Iam identifiers

Actions:
  * Thermostat:Get get the thermostat state
  * Thermostat:Set set the thermostat state

## Pairing

### First pairing

When the device starts up it has enabled Local Initial Pairing this means that
the first user which pairs with the device on the same LAN gets the admin/owner
privileges of the device.

After the first user has been paired the next users can pair using Password Open
Pairing or Local Open Pairing or Password Invite Pairing. This all depends on
how the device is setup by the first user.
