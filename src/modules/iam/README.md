# Nabto IAM module

The Nabto IAM module provides user access management for the embedded
SDK. To use this module, you must add the cmake file list
`${ne_iam_src}` defined in `nabto_primary_files.cmake` in the
repository root. Additionally, the module requires an implementation
of `src/api/nabto_device_threads.h`. For Windows,
`src/modules/threads/win/nabto_device_threads_win.c` can be used, for
unix based systems with pthread
`src/modules/threads/unix/nabto_device_threads_unix.c` can be
used. For custom targets, use the implementation created in the custom
platform integration. Finally, the IAM module must be linked with the
`nabto_device` library.

To begin using the compiled files, use the following headers:

 * `nm_iam_configuration.h`: Create configuration for the IAM module.
 * `nm_iam_state.h`: Create state for the IAM module.
 * `nm_iam.h`: The IAM module.
 * `nm_iam_serializer.h`: Serialize configuration and state structures
   to ease persisting.

## Usage

To use the IAM module, it need to be provided a configuration and some
state. The first time using the IAM module, these should be created
using `nm_iam_configuration.h` and `nm_iam_state.h`
respectively. These concepts are described further on
the
[Documentation site](https://docs.nabto.com/developer/guides/iam/intro.html). Once
these structures are created, they can be converted into a JSON string
using `nm_iam_serializer.h`, persisted, and loaded back into
structures using `nm_iam_serializer.h`.

 1. Create an IAM configuration and state as described.
 3. Create, initialize, load configuration, and load state into an IAM
    module using `nm_iam.h`.
 4. Persist the IAM state when a `nm_iam_state_changed` callback is
    received. eg. using `nm_iam_serializer.h`
 5. Use `nm_iam_check_access()` to determine if a request should be
    allowed.
 6. Repeat 4. and 5. as needed.
 7. Stop and deinitialize the IAM module
