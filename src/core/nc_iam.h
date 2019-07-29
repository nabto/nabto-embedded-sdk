#ifndef _NC_IAM_H_
#define _NC_IAM_H_

#include <platform/np_error_code.h>

#include "nc_iam_util.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

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
    const char* id;
    struct nc_iam_list roles;
};

struct nc_iam_value {
    enum nc_iam_value_type type;
    union {
        uint32_t number;
        char* string;
    } data;
};

struct nc_iam_attribute_name {
    const char* name;
};

struct nc_iam_attribute {
    struct nc_iam_attribute_name* name;
    struct nc_iam_value value;
};

struct nc_iam_policy {
    char* name;
    void* cbor;
    size_t cborLength;
};

struct nc_iam_role {
    char* name;
    struct nc_iam_list policies;
};

struct nc_iam_env {
    struct nc_iam* iam;
    struct nc_device_context* device;
    uint64_t connectionRef;
    struct nc_iam_list attributes;
    struct nc_iam_list policies;
};

void nc_iam_init(struct nc_iam* iam);
void nc_iam_deinit(struct nc_iam* iam);

struct nc_iam_user* nc_iam_find_user_by_fingerprint(struct nc_iam* iam, uint8_t fingerprint[16]);
struct nc_iam_user* nc_iam_find_user_by_name(struct nc_iam* iam, const char* name);

uint32_t nc_iam_get_user_count(struct nc_iam* iam);

bool nc_iam_check_access(struct nc_iam_env* env, const char* action);


void nc_iam_env_init_coap(struct nc_iam_env* env, struct nc_device_context* device, struct nabto_coap_server_request* request);
void nc_iam_env_deinit(struct nc_iam_env* env);

void nc_iam_attributes_add_string(struct nc_iam_env* env, const char* attributeName, const char* attribute);
void nc_iam_attributes_add_number(struct nc_iam_env* env, const char* attributeName, uint32_t number);

struct nc_iam_attribute* nc_iam_attribute_new();
void nc_iam_attribute_free(struct nc_iam_attribute* attribute);

// SYSTEM
np_error_code nc_iam_set_default_user(struct nc_iam* iam, const char* name);


// USERS
np_error_code nc_iam_create_user(struct nc_iam* iam, const char* name);
np_error_code nc_iam_user_add_role(struct nc_iam* iam, const char* user, const char* role);
np_error_code nc_iam_user_remove_role(struct nc_iam* iam, const char* user, const char* role);
np_error_code nc_iam_list_users(struct nc_iam* iam, void** cbor, size_t* cborLength);

// ROLES
np_error_code nc_iam_list_roles(struct nc_iam* iam, void** cbor, size_t* cborLength);
np_error_code nc_iam_create_role(struct nc_iam* iam, const char* name);
np_error_code nc_iam_delete_role(struct nc_iam* iam, const char* name);
np_error_code nc_iam_role_get(struct nc_iam* iam, const char* name, void** cbor, size_t* cborLength);

np_error_code nc_iam_role_add_policy(struct nc_iam* iam, const char* role, const char* policy);
np_error_code nc_iam_role_remove_policy(struct nc_iam* iam, const char* role, const char* policy);

#endif
