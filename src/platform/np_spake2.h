#ifndef _NP_SPAKE2_H_
#define _NP_SPAKE2_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
/**
 * Coap req for the key exchange. The request comes in, a password is
 * found for the username and a response is generated.
 */
struct nc_spake2_password_request {
    // the username and T comes from the coap request.
    char* username;
    uint8_t* T;
    size_t Tlen;
    uint8_t clientFingerprint[32];
    uint8_t deviceFingerprint[32];
    struct nc_coap_server_request* coapRequest;
    struct np_platform* pl;
};


struct np_spake2_module {
    np_error_code (*calculate_key)(struct nc_spake2_password_request* req,
                                   const char* password, uint8_t* resp,
                                   size_t* respLen, uint8_t* spake2Key);
    np_error_code (*key_confirmation)(uint8_t* payload, size_t payloadLen,
                                      uint8_t* key, size_t keyLen,
                                      uint8_t* hash1, size_t hash1Len);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
