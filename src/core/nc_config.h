#ifndef NC_CONFIG_H_
#define NC_CONFIG_H_

// The platform config file, NP_CONFIG_FILE, can override the defaults below.
#include <platform/np_config.h>

#include <stdint.h>

/**
 * Default resource limits.
 *
 * The limits can be changed at runtime with the nabto_device_limit_*
 * functions. No default fits both a small embedded device and a Linux
 * server, so they are unlimited unless the platform sets them here or the
 * application sets them at runtime. A device which is reachable by untrusted
 * clients should set them.
 */

// Concurrent client connections.
#ifndef NC_DEFAULT_MAX_CONNECTIONS
#define NC_DEFAULT_MAX_CONNECTIONS SIZE_MAX
#endif

// Concurrent streams.
#ifndef NC_DEFAULT_MAX_STREAMS
#define NC_DEFAULT_MAX_STREAMS SIZE_MAX
#endif

// Stream segments allocated across all streams. A segment holds up to 256
// bytes of data.
#ifndef NC_DEFAULT_MAX_STREAM_SEGMENTS
#define NC_DEFAULT_MAX_STREAM_SEGMENTS 1000000
#endif

// Concurrent CoAP server requests.
#ifndef NC_DEFAULT_MAX_COAP_SERVER_REQUESTS
#define NC_DEFAULT_MAX_COAP_SERVER_REQUESTS SIZE_MAX
#endif

// Size in bytes of a CoAP server request body, also when it is reassembled
// from Block1 blocks.
#ifndef NC_DEFAULT_MAX_COAP_SERVER_REQUEST_SIZE
#define NC_DEFAULT_MAX_COAP_SERVER_REQUEST_SIZE SIZE_MAX
#endif

// Size in bytes of a response body received by the CoAP client, which talks
// to the basestation, also when it is reassembled from Block2 blocks.
#ifndef NC_DEFAULT_MAX_COAP_CLIENT_RESPONSE_SIZE
#define NC_DEFAULT_MAX_COAP_CLIENT_RESPONSE_SIZE SIZE_MAX
#endif

#endif
