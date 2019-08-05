#ifndef _NC_IAM_H_
#define _NC_IAM_H_

#include <platform/np_error_code.h>

#include "nc_iam_util.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define NC_IAM_MAX_STRING_LENGTH 33

struct nc_client_connection;
struct nabto_coap_server_request;
struct nc_device_context;

enum nc_iam_evaluation_result {
    NC_IAM_EVALUATION_RESULT_NONE,
    NC_IAM_EVALUATION_RESULT_ALLOW,
    NC_IAM_EVALUATION_RESULT_DENY
};

enum nc_iam_value_type {
    NC_IAM_VALUE_TYPE_NUMBER,
    NC_IAM_VALUE_TYPE_STRING
};

enum nc_iam_predicate_type {
    NC_IAM_PREDICATE_TYPE_STRING_EQUAL,
    NC_IAM_PREDICATE_TYPE_NUMBER_EQUAL,
};

enum nc_iam_boolean_expression_type {
    NC_IAM_BOOLEAN_EXPRESSION_TYPE_AND,
    NC_IAM_BOOLEAN_EXPRESSION_TYPE_OR,
};

struct nc_iam_fingerprint {
    struct nc_iam_user* user;
    uint8_t fingerprint[16];
};

typedef void (*nc_iam_change_callback)(void* userData);

struct nc_iam {
    uint64_t version;
    struct nc_iam_list fingerprints;
    struct nc_iam_list users;
    struct nc_iam_list roles;
    struct nc_iam_list policies;
    struct nc_iam_user* defaultUser;
    nc_iam_change_callback changeCallback;
    void* changeCallbackUserData;
};

struct nc_iam_user {
    char id[NC_IAM_MAX_STRING_LENGTH];
    struct nc_iam_list roles;
};

struct nc_iam_value {
    enum nc_iam_value_type type;
    union {
        int64_t number;
        char string[NC_IAM_MAX_STRING_LENGTH];
    } data;
};

struct nc_iam_attribute {
    char name[NC_IAM_MAX_STRING_LENGTH];
    struct nc_iam_value value;
};

struct nc_iam_policy {
    char name[NC_IAM_MAX_STRING_LENGTH];
    void* cbor;
    size_t cborLength;
};

struct nc_iam_role {
    char name[NC_IAM_MAX_STRING_LENGTH];
    struct nc_iam_list policies;
};

#define NC_IAM_MAX_ATTRIBUTES 10

struct nc_iam_attributes {
    struct nc_iam_attribute attributes[NC_IAM_MAX_ATTRIBUTES];
    size_t used;
};

void nc_iam_init(struct nc_iam* iam);
void nc_iam_deinit(struct nc_iam* iam);

struct nc_iam_user* nc_iam_find_user_by_fingerprint(struct nc_iam* iam, const uint8_t fingerprint[16]);
struct nc_iam_user* nc_iam_find_user_by_name(struct nc_iam* iam, const char* name);
struct nc_iam_user* nc_iam_get_default_user(struct nc_iam* iam);

np_error_code nc_iam_check_access(struct nc_client_connection* connection, const char* action, void* attributesCbor, size_t attributesCborLength);

np_error_code nc_iam_attributes_add_string(struct nc_iam_attributes* attributes, const char* attributeName, const char* attribute);
np_error_code nc_iam_attributes_add_number(struct nc_iam_attributes* attributes, const char* attributeName, int64_t number);

// SYSTEM
np_error_code nc_iam_set_default_user(struct nc_iam* iam, const char* name);


// USERS
np_error_code nc_iam_create_user(struct nc_iam* iam, const char* name);
np_error_code nc_iam_list_users(struct nc_iam* iam, void* cborBuffer, size_t cborBufferLength, size_t* used);
np_error_code nc_iam_user_get(struct nc_iam* iam, const char* name, void* cborBuffer, size_t cborBufferLength, size_t* used);
np_error_code nc_iam_user_add_role(struct nc_iam* iam, const char* user, const char* role);
np_error_code nc_iam_user_remove_role(struct nc_iam* iam, const char* user, const char* role);
np_error_code nc_iam_user_add_fingerprint(struct nc_iam* iam, const char* user, const uint8_t fingerprint[16]);
np_error_code nc_iam_user_remove_fingerprint(struct nc_iam* iam, const char* user, const uint8_t fingerprint[16]);

// ROLES
np_error_code nc_iam_list_roles(struct nc_iam* iam, void** cbor, size_t* cborLength);
np_error_code nc_iam_create_role(struct nc_iam* iam, const char* name);
np_error_code nc_iam_delete_role(struct nc_iam* iam, const char* name);
np_error_code nc_iam_role_get(struct nc_iam* iam, const char* name, void** cbor, size_t* cborLength);

np_error_code nc_iam_role_add_policy(struct nc_iam* iam, const char* role, const char* policy);
np_error_code nc_iam_role_remove_policy(struct nc_iam* iam, const char* role, const char* policy);

/**
 * Copy a string, take NC_IAM_MAX_STRING_LENGTH into account.
 */
np_error_code nc_iam_str_cpy(char* dst, const char* src);


#endif
