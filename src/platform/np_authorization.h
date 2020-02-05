#ifndef NP_AUTHORIZATION_H
#define NP_AUTHORIZATION_H


struct np_platform;


struct np_authorization_request;

typedef void (*np_authorization_request_callback)(struct np_authorization_request* authorizationRequest, const np_error_code ec, void* userData);


struct np_authorization {

    struct np_authorization_request* (*create_request)(struct np_platform* pl, uint64_t connectionRef, const char* action);
    void (*free_request)(struct np_authorization_request* authorizationRequest);

    np_error_code (*add_number_attribute)(struct np_authorization_request* authorizationRequest, const char* key, int64_t value);
    np_error_code (*add_string_attribute)(struct np_authorization_request* authorizationRequest, const char* key, const char* value);

    /**
     * Check authorization
     *
     * @return true iff access is allowed.
     */
    void (*check_access)(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData);

};

#endif
