#ifndef NABTO_DEVICE_PLATFORM_H_
#define NABTO_DEVICE_PLATFORM_H_

#include <platform/np_error_code.h>

struct nabto_device_mutex;
struct np_platform;
struct nabto_device_context;
struct np_completion_event;

/**
 * Init a platform
 *
 * This function is called from the nabto_device_new function.
 *
 * @param pl  The platform to initialize.
 * @param coreMutex  The mutex which is used to synchronize calls to functions in the `nabto_device.h` api and the internal event queue, hence all functionality in the core is protected by this mutex.
 * @return NABTO_EC_OK  iff the platform is initialized.
 */
np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* coreMutex);

/**
 * Deinit a platform, this function is called from the nabto_device_free function.
 *
 * @param pl  The platform.
 */
void nabto_device_platform_deinit(struct nabto_device_context* device);

/**
 * Close the platform gracefully. This is called whenever nabto_device_close is
 * called, it makes it possible to e.g. gracefully close an embedded mdns server.
 */
void nabto_device_platform_close(struct nabto_device_context* device, struct np_completion_event* closeEvent);

/**
 * Blocking stop function of the platform. After this function returns
 * the platform is stopped and no further events or network
 * communication is happening.
 *
 * Every completion event given to the platform (udp, tcp, dns, mdns) has
 * been resolved when this function returns and no completion event is
 * resolved after it returns, since the core frees the memory the events
 * are in once the platform is stopped.
 *
 * @param pl  The platform.
 */
void nabto_device_platform_stop_blocking(struct nabto_device_context* device);


#endif
