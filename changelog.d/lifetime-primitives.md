### Added
 * CMake option `NABTO_DEVICE_LIFETIME_CHECKS`. When enabled, the device
   aborts on a broken resource lifetime contract, e.g. a completion event which
   is resolved twice or deinitialized while its operation is outstanding.
   Without the option such violations are logged as errors. It is meant for
   debug and test builds of the SDK and of custom platform integrations.

### Changed
 * The contract for custom platform integrations is now documented in the
   platform interface headers: every completion event given to a UDP, TCP, DNS
   or mDNS implementation is resolved exactly once, also when the operation is
   aborted, and no completion event is resolved after
   `nabto_device_platform_stop_blocking()` returns. A TCP read, write or
   connect started while the same operation is outstanding resolves the new
   completion event with `NABTO_EC_OPERATION_IN_PROGRESS`.

### Bug fixes
 * Fixed a race in the thread event queue used by the Linux and macOS
   platforms and by custom platforms built on `thread_event_queue`. An event
   which was cancelled or destroyed just as the event queue thread picked it
   up could still have its callback executed, after the event had been freed.
 * `thread_event_queue_stop_blocking()` no longer leaves the queue mutex
   locked when it is called on a queue which is already stopped.
