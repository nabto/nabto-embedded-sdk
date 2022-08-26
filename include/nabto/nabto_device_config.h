#ifndef _NABTO_DEVICE_CONFIG_H_
#define _NABTO_DEVICE_CONFIG_H_

#ifdef NABTO_DEVICE_USER_SETTINGS
#include "nabto_device_user_settings.h"
#endif

// Define to disable the std out log callback if using custom log callback
//#define NABTO_DEVICE_NO_LOG_STD_OUT_CALLBACK

// Define to enable log output from the DTLS module for debugging
//#define NABTO_DEVICE_DTLS_LOG

// Define to disable the password authentication feature
//#define NABTO_DEVICE_NO_PASSWORD_AUTHENTICATION

// Define to use Wolfssl as DTLS module instead of Mbedtls
//#define NABTO_DEVICE_WOLFSSL

// Define to make device function as DTLS Client for Nabto Client connections. Enabling this requires Nabto Clients v5.10.0 or greater. This completely removes the need for a DTLS server module.
//#define NABTO_DEVICE_DTLS_CLIENT_ONLY


// Check configuration section.

#ifndef NABTO_DEVICE_WOLFSSL
#define NABTO_DEVICE_MBEDTLS
#endif

#ifndef NABTO_DEVICE_NO_PASSWORD_AUTHENTICATION
#define NABTO_DEVICE_PASSWORD_AUTHENTICATION
#endif

#endif
