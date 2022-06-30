#ifndef _NP_SPAKE2_H_
#define _NP_SPAKE2_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct np_spake2_context;

struct np_spake2_module {
    np_error_code (*create)(struct np_platform* pl, struct np_spake2_context** spake);
    void (*destroy)(struct np_spake2_context* spake);
    np_error_code (*calculate_key)(struct np_spake2_context* spake,
                                   const char* password,
                                   uint8_t* fingerprintClient,
                                   uint8_t* fingerprintDevice
                                   );
    np_error_code (*key_confirmation)(struct np_spake2_context* spake,
                                     uint8_t* payload, size_t payloadLength);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
