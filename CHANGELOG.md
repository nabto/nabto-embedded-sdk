# Changelog

## [unreleased]

### Added
 * Friendly name for the device added to the IAM state. This results in the following additions:
 * * New IAM action: `IAM:SetDeviceInfo`. The Tcp Tunnel App also supports this, however, existing IAM configuration files must be recreated before users will have access to this action.
 * * New CoAP endpoint: `PUT /iam/device-info/friendly-name`
 * * A `FriendlyName` field is added to the CoAP response for `GET /iam/pairing`

### Bug Fixes
 * nabto_device_listener_stop returned another NabtoDeviceError than the documentation stated.



## [5.11.0]

### Added
 * limit functions from 5.6.0 moved out of experimental
 * simple_speed_test example to benchmark crypto operations
 * all dynamic memory allocation is done through a replacable memory allocator (src/platform/np_allocator.h)
 * `nabto_device_service_invocation_get_response_message_format()` function to help decode service invocation responses after more lax requirements from the basestation to the format of service invocation responses.
 * SDK can now be compiled with wolfssl instead of mbedtls with `NABTO_DEVICE_WOLFSSL`. Wolfssl must be installed on the system to work. Mbedtls is provided as submodule.
 * Password authentication can be disabled using `NABTO_DEVICE_NO_PASSWORD_AUTHENTICATION`
 * Device can now be compiled without a DTLS server using `NABTO_DEVICE_DTLS_CLIENT_ONLY`. In this mode, the Embedded SDK will respond with a DTLS clientHello request when a Nabto Client sends a clientHello request. When the Nabto Client receives a clientHello request, it will terminate its DTLS client connection, and start a DTLS server for the connection instead. This mode requires Nabto Client SDK v5.10.0 or later.
 * Simple examples adds `demosct` as server connect token to simplify example guides. This is simpler as remote client connections no longer requires a server key if they use server connect tokens.


### Changed
 * tcp_tunnel_device user experience updates
 * memory allocation updates to significantly reduce memory usage
 * fix some handling of device initialization failures


#### Breaking Changes

### Removed

## [5.7.0] - 2021-09-21

### Added
 * 3 new device events for failed attach attempts, `UNKNOWN_FINGERPRINT`, `WRONG_PRODUCT_ID`, `WRONG_DEVICE_ID`

### Changed
 * Fixed issues with attacher not resetting properly when disabling/enabling attach using `nabto_device_set_basestation_attach()`.
 * Fixed handling of sigpipe in TCP tunnels
 * fix several minor leaks/bugs


#### Breaking Changes

### Removed

## [5.6.0] - 2021-05-07

### Added
 - added protection against replay attacks in streams

#### Feature: Limit number of concurrent tcp tunnelling connections

We have added a feature such that the amount of concurrent tcp tunnelling
connections of a certain type can be limited. The limit is based on the tcp
tunnel service type. This feature can be used on devices where certain tcp
tunnels needs to be limited. It could be a device which both have RTSP and HTTP
services where RTSP needs to be limited to a single connections while HTTP can
have many connections. The feature can be controlled with the function
`nabto_device_tcp_tunnel_service_limit_concurrent_connections_by_type` which
currently resides in nabto_device_experimental.h

#### Feature: size limits in the IAM module

We have added max lengths to strings users can store in the IAM module to nm_iam.h to enable
developers to put a bound on the persistant storage space needed for the module. The number of users
that can be stored in the IAM module can also be limited.

#### Feature: control basestation attach

The `nabto_device_set_basestation_attach()` function is added to the API. This can be used to turn
basestation attach on or off both before `nabto_device_start()` and at runtime. This replaces the
`nabto_device_disable_remote_access()` function from the experimental header, which did not work at
runtime, and could not enable attach. This is useful in some user privacy situations where user
acceptance is required before contacting a remote server. In that case, attach would be disabled
before starting the device, but can then be enabled later without the requirement of starting a new
device.

### Changed
#### Password guess throttle

Password authentication towards the device is now throttled using a device global token bucket
filter instead of limiting attempts pr. connection. The token bucket has a default max size 10 and
only decreased by a client providing an invalid username or password. Meaning no throttling will
occur before 10 incorrect attempts has been made. After this, tokens are replenished at a default
rate of 1 pr. sec. This will increase usability connections no longer needs to be reconnected after
3 invalid attempts, while providing better protection against brute force password crack attacks.

#### Breaking Changes
`nabto_device_disable_remote_access()` in the experimental header is now deprecated. This being an
experimental function, it is likely to be removed completely in the near future.

### Removed

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
