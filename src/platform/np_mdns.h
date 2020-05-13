#ifndef NP_MDNS_H
#define NP_MDNS_H

#include <stdint.h>
#include <platform/np_error_code.h>

/**
 * Mdns server interface
 *
 * Warning: this interface will maybe change in the future.
 */

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

    /**
     * Create a new mdns server
     *
     * @param pl  The platform.
     * @param productId  The product id.
     * @param deviceId  The device id.
     * @param getPort  Callback to get the port.
     * @param getPortUserData  User data for the getPort callback.
     * @param mdns  The resulting mdns server object.
     * @return NABTO_EC_OK  Iff the mdns server was created.
     */
    np_error_code (*create)(struct np_platform* pl,
                           const char* productId, const char* deviceId,
                           np_mdns_get_port getPort, void* getPortUserData,
                           struct np_mdns_context** mdns);

    /**
     * Destroy a mdns server
     */
    void (*destroy)(struct np_mdns_context* mdns);

    /**
     * Start the mdns server
     */
    void (*start)(struct np_mdns_context* mdns);

    /**
     * Stop the mdns server
     */
    void (*stop)(struct np_mdns_context* mdns);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_MDNS_H
