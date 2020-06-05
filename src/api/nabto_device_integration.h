#ifndef _NABTO_DEVICE_INTEGRATION_H_
#define _NABTO_DEVICE_INTEGRATION_H_

#include <nabto/nabto_device.h>

struct np_udp;
struct np_tcp;
struct np_timestamp;
struct np_dns;
struct np_system_information;
struct np_event_queue;
struct nabto_device_context;
struct np_local_ip;
struct np_mdns;



/**
 * Set and get the opaque platform data. The pointer returned from the
 * get function is the pointer which is set in the set
 * function.
 */
void* nabto_device_integration_get_platform_data(struct nabto_device_context* device);

/**
 * Set the platform adapter.
 */
void nabto_device_integration_set_platform_data(struct nabto_device_context* device, void* data);

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
void nabto_device_integration_set_udp_impl(struct nabto_device_context* device, struct np_udp* obj);

/**
 * Set the TCP implementation which the device uses.
 *
 * This function should be called from nabto_device_platform_init.
 *
 * @param device  The device.
 * @param functions  Struct which contains the tcp functions to use. See src/platform/np_tcp.h.
 * @param data  Data pointer to be used with the tcp functions.
 */
void nabto_device_integration_set_tcp_impl(struct nabto_device_context* device, struct np_tcp* obj);

/**
 * Set the timestamp implementation which the device uses.
 */
void nabto_device_integration_set_timestamp_impl(struct nabto_device_context* device, struct np_timestamp* obj);

/**
 * Set the dns implementation which the device uses.
 */
void nabto_device_integration_set_dns_impl(struct nabto_device_context* device, struct np_dns* obj);

/**
 * Set the event queue implementation
 */
void nabto_device_integration_set_event_queue_impl(struct nabto_device_context* device, struct np_event_queue* obj);

/**
 * Set the local ip implementation.
 */
void nabto_device_integration_set_local_ip_impl(struct nabto_device_context* device, struct np_local_ip* obj);

/**
 * Set the mdns implementation
 */
void nabto_device_integration_set_mdns_impl(struct nabto_device_context* device, struct np_mdns* mdns);

#endif
