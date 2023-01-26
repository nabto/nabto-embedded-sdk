#ifndef _PRIVATE_KEY_H_
#define _PRIVATE_KEY_H_

#include <nabto/nabto_device.h>

#include <nn/log.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_file;


bool create_private_key(NabtoDevice* device, struct nm_file* fileImpl, const char* filename, struct nn_log* logger);
bool load_or_create_private_key(NabtoDevice* device, struct nm_file* fileImpl, const char* filename, struct nn_log* logger);

#ifdef __cplusplus
} // extern c
#endif

#endif
