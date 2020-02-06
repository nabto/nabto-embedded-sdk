#ifndef NP_AUTHORIZATION_H
#define NP_AUTHORIZATION_H


struct np_platform;


struct np_authorization_request;

typedef void (*np_authorization_request_callback)(bool allowed, void* userData1, void* userData2);


struct np_authorization {

    struct np_authorization_request* (*create_request)(struct np_platform* pl, uint64_t connectionRef, const char* action);

    np_error_code (*add_number_attribute)(struct np_authorization_request* authorizationRequest, const char* key, int64_t value);
    np_error_code (*add_string_attribute)(struct np_authorization_request* authorizationRequest, const char* key, const char* value);

    /**
     * Discard an authorization request. This should only be called if
     * check_access is not called, if the request could not be
     * prepared or is not used.
     */
    void (*discard_request)(struct np_authorization_request* authorizationRequest);

    /**
     * Check authorization
     *
     * The callback returns with true iff the request was allowed
     */
    void (*check_access)(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData1, void* userData2);

};

#endif
