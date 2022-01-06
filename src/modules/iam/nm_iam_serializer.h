#ifndef _NM_IAM_SERIALIZER_H_
#define _NM_IAM_SERIALIZER_H_

#include "nm_iam.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @intro Serializer
 *
 * Read and write a full IAM configuration and state.
 *
 * Header: `src/modules/iam/nm_iam_serializer.h`
 */

/**
 * Dump the IAM configuration to a JSON string for persistent
 * storage. The resulting string must be freed with
 * nm_iam_serializer_string_free().
 *
 * @param conf [in]   IAM configuration to dump
 * @param out [out]   Where to put serialized config
 * @return true iff the config was serialized successfully
 */
bool nm_iam_serializer_configuration_dump_json(struct nm_iam_configuration* conf, char** out);

/**
 * Load the IAM configuration from a JSON string.
 *
 * @param conf [in]   IAM configuration to load into
 * @param in   [in]   JSON string to load
 * @return true iff the configuration was successfully loaded
 */
bool nm_iam_serializer_configuration_load_json(struct nm_iam_configuration* conf, const char* in, struct nn_log* logger);

/**
 * Dump the IAM state to a JSON string for persistent storage. The
 * resulting string must be freed with
 * nm_iam_serializer_string_free().
 *
 * @param state [in]  State to dump from
 * @param out [out]   Where to put serialized state
 * @return true iff the state was serialized successfully
 */
bool nm_iam_serializer_state_dump_json(struct nm_iam_state* state, char** out);

/**
 * Load the IAM state from a JSON string.
 *
 * @param state [in]  State to load into
 * @param in [in]     JSON string to load
 * @return true iff the state was successfully loaded
 */
bool nm_iam_serializer_state_load_json(struct nm_iam_state* state, const char* in, struct nn_log* logger);

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
