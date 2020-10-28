#ifndef _NM_IAM_SERIALIZER_H_
#define _NM_IAM_SERIALIZER_H_

#include "nm_iam.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dump the IAM configuration to a JSON string for persistent
 * storage. The resulting string must be freed with
 * nm_iam_serializer_string_free().
 *
 * @param iam [in]    IAM module to dump from
 * @param out [out]   Where to put serialized config
 * @return true iff the config was serialized successfully
 */
bool nm_iam_serializer_config_dump(struct nm_iam* iam, char** out);

/**
 * Load the IAM configuration from a JSON string.
 *
 * @param iam [in]    IAM module to load config into
 * @param conf [in]   JSON string to load
 * @return true iff the config was successfully loaded
 */
bool nm_iam_serializer_config_load(struct nm_iam* iam, char* conf);

/**
 * Dump the IAM state to a JSON string for persistent storage. The
 * resulting string must be freed with
 * nm_iam_serializer_string_free().
 *
 * @param iam [in]    IAM module to dump from
 * @param out [out]   Where to put serialized state
 * @return true iff the state was serialized successfully
 */
bool nm_iam_serializer_state_dump(struct nm_iam* iam, char** out);

/**
 * Load the IAM state from a JSON string.
 *
 * @param iam [in]    IAM module to load state into
 * @param conf [in]   JSON string to load
 * @return true iff the state was successfully loaded
 */
bool nm_iam_serializer_state_load(struct nm_iam* iam, char* state);

/**
 * Free string returned by dump functions
 *
 * @param string  String to free
 */
void nm_iam_serializer_string_free(char* string);

#ifdef __cplusplus
} //extern "C"
#endif

#endif