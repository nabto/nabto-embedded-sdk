#ifndef _NABTO_DEVICE_PLATFORM_ADAPTER_H_
#define _NABTO_DEVICE_PLATFORM_ADAPTER_H_

#include <nabto/nabto_device.h>

struct np_udp;
struct np_tcp;
struct np_timestamp;
struct np_dns;
struct np_system_information;
struct np_event_queue;
struct nabto_device_context;
struct np_local_ip;



/**
 * Get the platform adapter. The platform adapter returned is the one
 * set in the set function.
 */
void* nabto_device_platform_adapter_get(struct nabto_device_context* device);

/**
 * Set the platform adapter.
 */
void nabto_device_platform_adapter_set(struct nabto_device_context* device, void* adapter);

/**
 * Set the UDP implementation which the device uses for UDP communication.
 *
 * This function should be called from the nabto_device_platform_init
 * function.
 *
 * @param device  The device.
 * @param functions  Struct which contains the udp functions to use. See src/platform/np_udp.h. (Object virtual table.)
 * @param data  opaque data for the udp instance. (Object instance data).
 */
void nabto_device_platform_adapter_set_udp(struct nabto_device_context* device, struct np_udp* obj);

/**
 * Set the TCP implementation which the device uses.
 *
 * This function should be called from nabto_device_platform_init.
 *
 * @param device  The device.
 * @param functions  Struct which contains the tcp functions to use. See src/platform/np_tcp.h.
 * @param data  Data pointer to be used with the tcp functions.
 */
void nabto_device_platform_adapter_set_tcp(struct nabto_device_context* device, struct np_tcp* obj);

/**
 * Set the timestamp implementation which the device uses.
 */
void nabto_device_platform_adapter_set_timestamp(struct nabto_device_context* device, struct np_timestamp* obj);

/**
 * Set the dns implementation which the device uses.
 */
void nabto_device_platform_adapter_set_dns(struct nabto_device_context* device, struct np_dns* obj);

/**
 * Set the system information implementation which the device uses.
 */
void nabto_device_platform_adapter_set_system_information(struct nabto_device_context* device, struct np_system_information* obj);

/**
 * Set the event queue object
 */
void nabto_device_platform_adapter_set_event_queue(struct nabto_device_context* device, struct np_event_queue* obj);

/**
 *
 */
void nabto_device_platform_adapter_set_local_ip(struct nabto_device_context* device, struct np_local_ip* obj);

#endif
