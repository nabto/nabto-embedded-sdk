#ifndef _TCP_TUNNEL_DEFAULT_POLICIES_H_
#define _TCP_TUNNEL_DEFAULT_POLICIES_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool init_default_policies(const char* fileName);

//bool load_policies(const char* fileName, nabto::fingerprint_iam::FingerprintIAM& iam);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
