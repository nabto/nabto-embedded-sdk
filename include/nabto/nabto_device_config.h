#ifndef NABTO_DEVICE_CONFIG_H_
#define NABTO_DEVICE_CONFIG_H_

/**
 * If building using Cmake, configurations should NOT be made through header
 * files. Instead run the cmake command with `-D<CONFIG>=ON` argument (eg. `cmake
 * -DNABTO_DEVICE_WOLFSSL=ON ../`). If building with another build system, create
 * the `nabto_device_user_configuration.h` file with the desired configuration
 * and set the `NABTO_DEVICE_USER_CONFIGURATION` definition.
 */
#ifdef NABTO_DEVICE_USER_CONFIG
#include "nabto_device_user_config.h"
#endif

// Define to disable the std out log callback on systems where it is not available
//#define NABTO_DEVICE_NO_LOG_STD_OUT_CALLBACK

// Define to enable log output from the DTLS module for debugging
//#define NABTO_DEVICE_DTLS_LOG

// Define to disable the password authentication feature
//#define NABTO_DEVICE_NO_PASSWORD_AUTHENTICATION

// Define to use Wolfssl as DTLS module instead of Mbedtls
//#define NABTO_DEVICE_WOLFSSL

// Define to make device function as DTLS Client for Nabto Client connections. Enabling this requires Nabto Clients v5.10.0 or greater. This completely removes the need for a DTLS server module in the device.
//#define NABTO_DEVICE_DTLS_CLIENT_ONLY

// Internal configuration section.

#ifndef NABTO_DEVICE_WOLFSSL
#define NABTO_DEVICE_MBEDTLS
#endif

#ifndef NABTO_DEVICE_NO_PASSWORD_AUTHENTICATION
#define NABTO_DEVICE_PASSWORD_AUTHENTICATION
#endif


/**
 * This is an experimental feature which allows the device to run without a
 * dedicated future queue but instead use the default event queue for resolving
 * futures. This is useful for devices running using a single event loop. Or for
 * simpler integrations where one just needs to come with the event_queue.
 */
//#define NABTO_DEVICE_NO_FUTURE_QUEUE
#ifndef NABTO_DEVICE_NO_FUTURE_QUEUE
#define NABTO_DEVICE_FUTURE_QUEUE
#endif

#endif
