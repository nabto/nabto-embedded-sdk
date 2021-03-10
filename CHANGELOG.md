# Changelog

## [5.5.0] - 2021-03-10

### Added

 - Service invocation api
 - Service invocation example

#### Feature: Service Invocation

A feature has been added such that the device can invoke an https service
through the basestation. The device uses the connection between the device and
the basestation to instruct the basestation to invoke an https service. The
service which is invoked is configured in the nabto cloud console.


## [5.3.0] - 2021-01-27

### Added

 - Simple MDNS example
 - Simple Push Device example

#### Feature: Push Notifications through FCM

The device has been given the functionality to send push notifications to
subscribing clients. The system is using FCM to send the actual messages. It is
implemented transparent such that most options from FCM send is available to the
device sending the push notifications.

### Changes

 - FCM Token, project id and notification categories has been added to IAM users
   and serialization formats for the IAM persistence functionality.

#### Breaking Changes


## [5.2.0] - 2020-10-24

### Added

 - Custom mDNS txtItems
 - Custom mDNS subtypes
 - PAKE based password authentication
 - Direct UDP ping to be used with direct candidates for a better user experience.

### Changed

### Breaking Changes

#### The experimental IAM system from 5.1 is incompatible with the stable iam system in 5.2

IAM was included in 5.1 as an experimental feature, we have had some feedback and changed several coap paths and functions. The overall functionality is the same.

#### The signature for the function post_maybe_double has changed.

The event queue function which can double post events has changed signature.
Before the function returned void now it returns a boolean describing if the event was posted to the event queue or discarded because it was double posted.

```
void (*post_maybe_double)(struct np_event* event);
```

to

```
bool (*post_maybe_double)(struct np_event* event);
```

This should give a compile time error/warning.

#### The mdns interface signature has been changed.

The mdns signature is changed from

```
void (*publish_service)(struct np_mdns* obj, uint16_t port, const char* productId, const char* deviceId);
```

to

```
void(*publish_service)(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems);
```

This should give a compile time error.

## [5.1.1] - 2020-08-03

### Changed
 - Fixed attach issue if multiple basestations where available.

## [5.1] - 2020-06-30

### Added

 - Platform adapters
 - TCP tunnelling
 - Server Connect Tokens
 - Authorization API

### Changed

### Removed

## [5.0] - 2019-12-01

Release of Nabto edge.
