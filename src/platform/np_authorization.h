#ifndef NP_AUTHORIZATION_H
#define NP_AUTHORIZATION_H

#include "np_error_code.h"
/**
 * Authorization interface
 *
 * Warning: This interface will maybe change in the future.
 */

struct np_platform;


struct np_authorization_request;

typedef void (*np_authorization_request_callback)(bool allowed, void* userData1, void* userData2, void* userData3);


struct np_authorization {

    /**
     * Create an authorization request, if the request cannot be made, the function returns NULL.
     */
    struct np_authorization_request* (*create_request)(struct np_platform* pl, uint64_t connectionRef, const char* action);

    /**
     * @param authorizationRequest if NULL the function returns OUT_OF_MEMORY.
     */
    np_error_code (*add_string_attribute)(struct np_authorization_request* authorizationRequest, const char* key, const char* value);

    /**
     * Discard an authorization request. This should only be called if
     * check_access is not called, if the request could not be
     * prepared or is not used.
     *
     * @param authorizationRequest  if NULL nothing happens.
     */
    void (*discard_request)(struct np_authorization_request* authorizationRequest);

    /**
     * Check authorization, call exactly one of them.
     *
     * The callback returns with true iff the request was allowed
     */
    void (*check_access)(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData1, void* userData2, void* userData3);

};

#endif
