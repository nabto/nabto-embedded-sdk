#ifndef NONE_AUTHORIZATION_H
#define NONE_AUTHORIZATION_H

#include <nabto/nabto_device.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_none_authorization(NabtoDevice* device);
void deinit_none_authorization();

#ifdef __cplusplus
} // extern "C"
#endif


#endif
