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
