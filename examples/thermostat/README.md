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

### `config/device.json`

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

A Day/Night schedule:

  * Two schedule entries, Day and Night, each with a target temperature, a
    time of day and an enabled flag. Once per minute the device checks the
    local time and when an enabled entry matches the current HH:MM its target
    is applied as the thermostat target temperature.

A 24 hour temperature history:

  * The room temperature is sampled every 5 minutes into an in memory ring
    buffer which is not persisted. On startup the buffer is seeded with a
    synthetic curve ending at the current temperature.

### CoAP endpoints

#### GET /thermostat

Requires the IAM action `Thermostat:Get`. Returns 205 with a CBOR map:

```
{
  "Mode": tstr ("COOL"|"HEAT"|"DRY"|"FAN"),
  "Target": double,
  "Power": bool,
  "Temperature": double,
  "Schedule": {
    "Day":   { "Target": double, "Time": tstr "HH:MM", "Enabled": bool },
    "Night": { "Target": double, "Time": tstr "HH:MM", "Enabled": bool }
  }
}
```

Defaults on fresh state: Day 21.0 / "06:30" / enabled, Night 18.0 / "22:00" /
enabled.

#### POST /thermostat/schedule/{id}

Requires the IAM action `Thermostat:Set`. `{id}` is `day` or `night`
(lowercase). The body is a CBOR map with any subset of the keys `Target`
(double), `Time` (tstr "HH:MM") and `Enabled` (bool). Missing keys leave the
corresponding field unchanged. Responses: 204 on success, 400 on bad input,
403 without access and 404 for an unknown id.

#### GET /thermostat/history

Requires the IAM action `Thermostat:Get`. Returns 205 with a CBOR map:

```
{
  "Interval": uint (seconds between samples, 300),
  "Samples": [ double, ... ]  // room temperature, oldest first, newest last
}
```

#### POST /thermostat/mode, /thermostat/target, /thermostat/power

Existing setters, unchanged. The legacy `/heat-pump` aliases only exist for
the original endpoints, not for the schedule and history endpoints.

### State stream on port 655

Clients can open a Nabto stream on stream port 655 over an existing
connection. Opening the stream requires the IAM action `Thermostat:Get`,
otherwise the stream is not accepted and the open fails in the client.

The device pushes the full state to the client immediately after the stream
is opened and then again on every state change, so clients do not need to
poll GET /thermostat. Messages are only sent from the device to the client.
Each message is a 4 byte big endian unsigned length followed by exactly that
many bytes of CBOR: a map identical to the GET /thermostat response.

Updates are throttled to at most one message per second and only sent when
the temperature has changed at least 0.05 degrees or the mode, power, target
or schedule has changed since the last sent message. Data sent by the client
is read and discarded, it is only used to detect that the client has closed
the stream.

### Iam identifiers

Actions:
  * Thermostat:Get get the thermostat state, history and state stream
  * Thermostat:Set set the thermostat state and schedule

## Pairing

### First pairing

When the device starts up it has enabled Local Initial Pairing this means that
the first user which pairs with the device on the same LAN gets the admin/owner
privileges of the device.

After the first user has been paired the next users can pair using Password Open
Pairing or Local Open Pairing or Password Invite Pairing. This all depends on
how the device is setup by the first user.
