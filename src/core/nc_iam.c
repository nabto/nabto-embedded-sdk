#include "nc_iam.h"
#include "nc_iam_policy.h"
#include "nc_iam_cbor.h"

#include "nc_device.h"
#include "nc_coap_server.h"

#include <cbor.h>

#include <string.h>
#include <stdlib.h>

static enum nc_iam_evaluation_result nc_iam_evaluate_policy(struct nc_iam_env* env, const char* action, struct nc_iam_policy* policy);
static enum nc_iam_evaluation_result nc_iam_evaluate_statement(struct nc_iam_env* env, const char* action, CborValue* statement);
static struct nc_iam_attribute* nc_iam_env_find_attribute(struct nc_iam_env* env, const char* attributeName);

static bool nc_iam_check_conditions(struct nc_iam_env* env, CborValue* conditions);
static bool nc_iam_check_condition(struct nc_iam_env* env, CborValue* condition);

void nc_iam_init(struct nc_iam* iam)
{
    iam->version = 0;
    iam->changeCallback = NULL;
    iam->changeCallbackUserData = NULL;
    nc_iam_list_init(&iam->fingerprints);
    nc_iam_list_init(&iam->users);
    nc_iam_list_init(&iam->roles);
    nc_iam_list_init(&iam->policies);
    iam->defaultUser = NULL;
}

void nc_iam_deinit(struct nc_iam* iam)
{

}

void nc_iam_updated(struct nc_iam* iam)
{
    iam->version++;
    if (iam->changeCallback) {
        iam->changeCallback(iam->changeCallbackUserData);
    }
}


struct nc_iam_user* nc_iam_find_user_by_fingerprint(struct nc_iam* iam, uint8_t fingerprint[16])
{
    return iam->defaultUser;
}

bool nc_iam_check_access(struct nc_iam_env* env, const char* action)
{
    struct nc_client_connection* connection = nc_device_connection_from_ref(env->device, env->connectionRef);
    if (!connection) {
        return false;
    }

    struct nc_iam_user* user = connection->user;

    nc_iam_attributes_add_string(env, "Connection:UserId", connection->user->id);

    bool granted = false;
    struct nc_iam_list_entry* roleIterator = user->roles.sentinel.next;
    while(roleIterator != &user->roles.sentinel) {
        struct nc_iam_role* role = (struct nc_iam_role*)roleIterator->item;
        struct nc_iam_list_entry* policyIterator = role->policies.sentinel.next;
        while(policyIterator != & role->policies.sentinel) {
            struct nc_iam_policy* policy = (struct nc_iam_policy*)policyIterator->item;
            enum nc_iam_evaluation_result result = nc_iam_evaluate_policy(env, action, policy);
            if (result == NC_IAM_EVALUATION_RESULT_NONE) {
                // no change
            } else if (result == NC_IAM_EVALUATION_RESULT_ALLOW) {
                granted = true;
            } else if (result == NC_IAM_EVALUATION_RESULT_DENY) {
                granted = false;
            }
            policyIterator = policyIterator->next;
        }
        roleIterator = roleIterator->next;
    }
    return granted;
    return false;
}

enum nc_iam_evaluation_result nc_iam_evaluate_policy(struct nc_iam_env* env, const char* action, struct nc_iam_policy* policy)
{
    CborParser parser;
    CborValue map;
    CborValue version;
    CborValue statements;

    cbor_parser_init(policy->cbor, policy->cborLength, 0, &parser, &map);

    cbor_value_map_find_value(&map, "Version", &version);
    int v;
    if (!cbor_value_is_integer(&version) ||
        !cbor_value_get_int(&version, &v) ||
        v != 1)
    {
        // Could not parse policy. A unparseable policy should not end in an accept so default to deny.
        return NC_IAM_EVALUATION_RESULT_DENY;
    }

    cbor_value_map_find_value(&map, "Statements", &statements);

    if (!cbor_value_is_array(&statements)) {
        return NC_IAM_EVALUATION_RESULT_DENY;
    }
    enum nc_iam_evaluation_result currentResult = NC_IAM_EVALUATION_RESULT_NONE;
    CborValue statement;
    cbor_value_enter_container(&statements, &statement);
    while (!cbor_value_at_end(&statement)) {
        enum nc_iam_evaluation_result result = nc_iam_evaluate_statement(env, action, &statement);
        if (result != NC_IAM_EVALUATION_RESULT_NONE) {
            currentResult = result;
        }
        cbor_value_advance(&statement);
    }

    return currentResult;
}

enum nc_iam_evaluation_result nc_iam_evaluate_statement(struct nc_iam_env* env, const char* actionStr, CborValue* statement)
{
    if (!cbor_value_is_map(statement)) {
        return NC_IAM_EVALUATION_RESULT_DENY;
    }
    CborValue actions;
    CborValue allow;
    CborValue conditions;

    cbor_value_map_find_value(statement, "Actions", &actions);
    cbor_value_map_find_value(statement, "Allow", &allow);
    cbor_value_map_find_value(statement, "Conditions", &conditions);

    if (!cbor_value_is_array(&actions) ||
        !cbor_value_is_boolean(&actions))
    {
        return NC_IAM_EVALUATION_RESULT_DENY;
    }

    bool allowAction;
    cbor_value_get_boolean(&allow, &allowAction);

    CborValue action;
    bool found = false;
    cbor_value_enter_container(&actions, &action);
    while(!cbor_value_at_end(&action)) {
        bool result;
        if (cbor_value_text_string_equals(&action, actionStr, &result) != CborNoError) {
            // cannot parse statement
            return NC_IAM_EVALUATION_RESULT_DENY;
        }
        if (result == true) {
            found = true;
            break;
        }
        cbor_value_advance(&action);
    }
    cbor_value_leave_container(&actions, &action);

    bool conditionsOk = nc_iam_check_conditions(env, &conditions);
    if (found && conditionsOk) {

        if (allowAction) {
            return NC_IAM_EVALUATION_RESULT_ALLOW;
        } else {
            return NC_IAM_EVALUATION_RESULT_DENY;
        }
    }
    return NC_IAM_EVALUATION_RESULT_NONE;
}

bool nc_iam_check_conditions(struct nc_iam_env* env, CborValue* conditions)
{
    if (cbor_value_is_null(conditions)) {
        return true;
    }
    if (!cbor_value_is_array(conditions))
    {
        // conditions must be nonexisting or an array.
        return false;
    }

    CborValue condition;
    cbor_value_enter_container(conditions, &condition);
    while(!cbor_value_at_end(&condition))
    {
        if (!nc_iam_check_condition(env, &condition)) {
            return false;
        }
        cbor_value_advance(&condition);
    }
    cbor_value_leave_container(conditions, &condition);
    return true;
}

bool nc_iam_check_condition(struct nc_iam_env* env, CborValue* condition)
{
    if (!cbor_value_is_map(condition)) {
        return false;
    }

    CborValue stringEqual;
    CborValue numberEqual;
    CborValue attributeEqual;
    cbor_value_map_find_value(condition, "StringEqual", &stringEqual);
    cbor_value_map_find_value(condition, "NumberEqual", &numberEqual);
    cbor_value_map_find_value(condition, "AttributeEqual", &attributeEqual);

    if (cbor_value_is_map(&stringEqual)) {

    } else if (cbor_value_is_map(&numberEqual)) {

    } else if (cbor_value_is_map(&attributeEqual)) {

    } else {
        // unknown condition
        return false;
    }
// todo
    return false;
}

bool nc_iam_string_equal(struct nc_iam_env* env, CborValue* parameters)
{
    char attributeName[33];
    CborValue parameter;
    cbor_value_enter_container(parameters, &parameter);
    if (!nc_iam_cbor_get_string(&parameter, attributeName, 33)) {
        return false;
    }
    cbor_value_advance(&parameter);
    if (!cbor_value_is_text_string(&parameter)) {
        return false;
    }

    struct nc_iam_attribute* attribute = nc_iam_env_find_attribute(env, attributeName);
    if (!attribute || attribute->value.type != NC_IAM_VALUE_TYPE_STRING) {
        return false;
    }

    bool matches;
    return (cbor_value_text_string_equals(&parameter, attribute->value.data.string, &matches) && matches);
}

bool nc_iam_number_equal(struct nc_iam_env* env, CborValue* parameters)
{
    char attributeName[33];
    CborValue parameter;
    cbor_value_enter_container(parameters, &parameter);
    if (!nc_iam_cbor_get_string(&parameter, attributeName, 33)) {
        return false;
    }
    cbor_value_advance(&parameter);
    if (!cbor_value_is_text_string(&parameter)) {
        return false;
    }

    struct nc_iam_attribute* attribute = nc_iam_env_find_attribute(env, attributeName);
    if (!attribute || attribute->value.type != NC_IAM_VALUE_TYPE_NUMBER) {
        return false;
    }
    int64_t value;
    if (!cbor_value_is_integer(&parameter) || !cbor_value_get_int64(&parameter, &value)) {
        return false;
    }

    return (attribute->value.data.number == value);
}

bool nc_iam_attribute_equals(struct nc_iam_env* env, CborValue* parameters)
{
    char attributeName1[33];
    char attributeName2[33];
    CborValue parameter;
    cbor_value_enter_container(parameters, &parameter);
    if (!nc_iam_cbor_get_string(&parameter, attributeName1, 33)) {
        return false;
    }
    cbor_value_advance(&parameter);
    if (!nc_iam_cbor_get_string(&parameter, attributeName2, 33)) {
        return false;
    }

    struct nc_iam_attribute* attribute1 = nc_iam_env_find_attribute(env, attributeName1);
    struct nc_iam_attribute* attribute2 = nc_iam_env_find_attribute(env, attributeName2);
    if (!attribute1 || !attribute2) {
        return false;
    }

    if (attribute1->value.type == NC_IAM_VALUE_TYPE_NUMBER && attribute2->value.type == NC_IAM_VALUE_TYPE_NUMBER) {
        return (attribute1->value.data.number == attribute2->value.data.number);
    } else if (attribute1->value.type == NC_IAM_VALUE_TYPE_STRING && attribute2->value.type == NC_IAM_VALUE_TYPE_STRING) {
        return (strcmp(attribute1->value.data.string, attribute2->value.data.string) == 0);
    }

    return false;
}

struct nc_iam_attribute* nc_iam_env_find_attribute(struct nc_iam_env* env, const char* attributeName)
{
    struct nc_iam_list_entry* iterator = env->attributes.sentinel.next;
    while (iterator !=&env->attributes.sentinel) {
        struct nc_iam_attribute* a = iterator->item;
        if (strcmp(a->name->name, attributeName) == 0) {
            return a;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void nc_iam_env_init_coap(struct nc_iam_env* env, struct nc_device_context* device, struct nabto_coap_server_request* request)
{
    env->iam = &device->iam;
    env->device = device;
    struct nc_client_connection* connection = nc_coap_server_get_connection(&device->coap, request);
    env->connectionRef = connection->connectionRef;
    nc_iam_list_init(&env->attributes);
}

void nc_iam_env_deinit(struct nc_iam_env* env)
{
    struct nc_iam_list_entry* iterator = env->attributes.sentinel.next;
    while(iterator != &env->attributes.sentinel) {
        struct nc_iam_attribute* current = iterator->item;
        iterator = iterator->next;
        nc_iam_attribute_free(current);
    }
    nc_iam_list_clear(&env->attributes);
}

void nc_iam_attributes_add_string(struct nc_iam_env* env, const char* attributeName, const char* attribute)
{
    // TODO
}

void nc_iam_attributes_add_number(struct nc_iam_env* env, const char* attributeName, uint32_t number)
{
    // TODO
}

struct nc_iam_attribute* nc_iam_attribute_new()
{
    return calloc(1, sizeof(struct nc_iam_attribute));
}

void nc_iam_attribute_free(struct nc_iam_attribute* attribute)
{
    if (attribute->value.type == NC_IAM_VALUE_TYPE_STRING) {
        free(attribute->value.data.string);
    }
    free(attribute);
}

uint32_t nc_iam_get_user_count(struct nc_iam* iam)
{
    // TODO
    return 42;
}

np_error_code nc_iam_set_default_user(struct nc_iam* iam, const char* name)
{
    struct nc_iam_user* user = nc_iam_find_user_by_name(iam, name);
    if (!user) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    iam->defaultUser = user;
    return NABTO_EC_OK;
}

struct nc_iam_role* nc_iam_find_role_by_name(struct nc_iam* iam, const char* name)
{
    struct nc_iam_list_entry* iterator = iam->roles.sentinel.next;
    while(iterator != &iam->roles.sentinel)
    {
        struct nc_iam_role* role = iterator->item;
        if (strcmp(role->name, name) == 0) {
            return role;
        }
        iterator = iterator->next;
    }
    return NULL;

}

np_error_code nc_iam_create_role(struct nc_iam* iam, const char* name)
{
    struct nc_iam_role* r = nc_iam_find_role_by_name(iam, name);
    if (r) {
        return NABTO_EC_RESOURCE_EXISTS;
    }
    r = calloc(1, sizeof(struct nc_iam_role));
    r->name = strdup(name);
    nc_iam_list_init(&r->policies);
    nc_iam_list_insert(&iam->roles, r);
    return NABTO_EC_OK;
}

np_error_code nc_iam_delete_role(struct nc_iam* iam, const char* name)
{
    struct nc_iam_role* role = nc_iam_find_role_by_name(iam, name);
    if (!name) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    // find users using the role if found, do not delete it.
    struct nc_iam_list_entry* iterator = iam->users.sentinel.next;
    while (iterator != &iam->users.sentinel) {
        struct nc_iam_user* user = iterator->item;
        struct nc_iam_list_entry* roleIterator = user->roles.sentinel.next;
        while(roleIterator != &user->roles.sentinel) {
            if (roleIterator->item == role) {
                return NABTO_EC_RESOURCE_IN_USE;
            }
            roleIterator = roleIterator->next;
        }
        iterator = iterator->next;
    }

    // role is found and not in use.

    nc_iam_list_remove_item(&iam->roles, role);
    free(role->name);
    nc_iam_list_clear(&role->policies);
    free(role);
    return NABTO_EC_OK;
}

np_error_code nc_iam_list_roles(struct nc_iam* iam, void** cbor, size_t* cborLength)
{
    uint8_t buffer[1024];

    CborEncoder encoder;
    CborEncoder array;
    cbor_encoder_init(&encoder, buffer, 1024, 0);
    cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);

    struct nc_iam_list_entry* iterator = iam->roles.sentinel.next;
    while(iterator != &iam->roles.sentinel) {
        struct nc_iam_role* role = iterator->item;
        cbor_encode_text_stringz(&array, role->name);
        iterator = iterator->next;
    };
    cbor_encoder_close_container(&encoder, &array);

    size_t used = cbor_encoder_get_buffer_size(&encoder, buffer);
    *cbor = malloc(used);
    if (*cbor == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    memcpy(*cbor, buffer, used);
    *cborLength = used;
    return NABTO_EC_OK;
}

np_error_code nc_iam_role_get(struct nc_iam* iam, const char* name, void** cbor, size_t* cborLength)
{
    uint8_t buffer[1024];
    CborEncoder encoder;
    CborEncoder array;
    CborEncoder map;

    struct nc_iam_role* role = nc_iam_find_role_by_name(iam, name);
    if (!role) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }

    cbor_encoder_init(&encoder, buffer, 1024, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "Policies");
    cbor_encoder_create_array(&map, &array, CborIndefiniteLength);

    struct nc_iam_list_entry* iterator = role->policies.sentinel.next;
    while(iterator != &role->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        cbor_encode_text_stringz(&array, p->name);
        iterator = iterator->next;
    }
    cbor_encoder_close_container(&map, &array);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, buffer);
    *cbor = malloc(used);
    if (*cbor == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    memcpy(*cbor, buffer, used);
    *cborLength = used;
    return NABTO_EC_OK;
}

struct nc_iam_user* nc_iam_find_user_by_name(struct nc_iam* iam, const char* name)
{
    struct nc_iam_list_entry* iterator = iam->users.sentinel.next;
    while(iterator != &iam->users.sentinel) {
        struct nc_iam_user* u = iterator->item;
        if (strcmp(u->id, name) == 0) {
            return u;
        }
        iterator = iterator->next;
    }
    return NULL;
}

np_error_code nc_iam_create_user(struct nc_iam* iam, const char* name)
{
    struct nc_iam_user* existing = nc_iam_find_user_by_name(iam, name);
    if (existing) {
        return NABTO_EC_RESOURCE_EXISTS;
    }

    struct nc_iam_user* user = calloc(1, sizeof(struct nc_iam_user));
    user->id = strdup(name);
    nc_iam_list_init(&user->roles);
    nc_iam_list_insert(&iam->users, user);
    return NABTO_EC_OK;
}

np_error_code nc_iam_user_add_role(struct nc_iam* iam, const char* user, const char* role)
{
    struct nc_iam_user* u = nc_iam_find_user_by_name(iam, user);
    struct nc_iam_role* r = nc_iam_find_role_by_name(iam, role);
    if (!u || !r) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    nc_iam_list_insert(&u->roles, r);
    return NABTO_EC_OK;
}

np_error_code nc_iam_user_remove_role(struct nc_iam* iam, const char* user, const char* role)
{
    struct nc_iam_user* u = nc_iam_find_user_by_name(iam, user);
    struct nc_iam_role* r = nc_iam_find_role_by_name(iam, role);
    if (!u || !r) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    nc_iam_list_remove_item(&u->roles, r);
    return NABTO_EC_OK;
}


np_error_code nc_iam_role_add_policy(struct nc_iam* iam, const char* role, const char* policy)
{
    struct nc_iam_role* r = nc_iam_find_role_by_name(iam, role);
    struct nc_iam_policy* p = nc_iam_find_policy_by_name(iam, policy);
    if (!r || !p) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }

    nc_iam_list_insert(&r->policies, p);
    return NABTO_EC_OK;
}

np_error_code nc_iam_role_remove_policy(struct nc_iam* iam, const char* role, const char* policy)
{
    struct nc_iam_role* r = nc_iam_find_role_by_name(iam, role);
    struct nc_iam_policy* p = nc_iam_find_policy_by_name(iam, policy);
    if (!r || !p) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    nc_iam_list_remove_item(&r->policies, p);
    return NABTO_EC_OK;
}
