#ifndef NP_MDNS_H
#define NP_MDNS_H

#include <stdint.h>
#include <platform/np_error_code.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_mdns_context;
struct np_platform;

// callback to the implementer of the module to get the current port
// number for the service. if the port number is 0 the answer is
// invalid.
typedef uint16_t (*np_mdns_get_port)(void* userData);

struct np_mdns_module {
    np_error_code (*start)(struct np_mdns_context** mdns, struct np_platform* pl,
                           const char* productId, const char* deviceId,
                           np_mdns_get_port getPort, void* userData);

    void (*stop)(struct np_mdns_context* mdns);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_MDNS_H
