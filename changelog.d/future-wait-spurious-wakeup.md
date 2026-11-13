### Bug fixes
 * `nabto_device_future_wait` could return before the future was resolved
   when the condition variable woke up spuriously, which the operating system
   is allowed to do. It then returned `NABTO_DEVICE_EC_OK` for an operation
   which had not completed. It now waits until the future is resolved.
