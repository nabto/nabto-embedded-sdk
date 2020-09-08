# Changelog

## [Unreleased]

### Added

 - Custom mDNS txtItems
 - Custom mDNS subtypes
 - PAKE based password authentication
 - Direct UDP ping to be used with direct candidates for a better user experience.

### Changed

### Breaking Changes

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
