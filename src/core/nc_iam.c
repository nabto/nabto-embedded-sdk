#include "nc_iam.h"
#include "nc_iam_policy.h"
#include "nc_iam_cbor.h"
#include "nc_iam_dump.h"
#include "nc_iam_util.h"

#include "nc_device.h"
#include "nc_coap_server.h"

#include <cbor.h>

#include <string.h>
#include <stdlib.h>

static enum nc_iam_evaluation_result nc_iam_evaluate_policy(struct nc_iam_attributes* attributes, const char* action, struct nc_iam_policy* policy);
static enum nc_iam_evaluation_result nc_iam_evaluate_statement(struct nc_iam_attributes* attributes, const char* action, CborValue* statement);
static struct nc_iam_attribute* nc_iam_attributes_find_attribute(struct nc_iam_attributes* attributes, const char* attributeName);

static np_error_code nc_iam_check_conditions(struct nc_iam_attributes* attributes, CborValue* conditions);
static np_error_code nc_iam_check_condition(struct nc_iam_attributes* attributes, CborValue* condition);
static np_error_code nc_iam_string_equal(struct nc_iam_attributes* attributes, CborValue* parameters);
static np_error_code nc_iam_number_equal(struct nc_iam_attributes* attributes, CborValue* parameters);
static np_error_code nc_iam_attribute_equal(struct nc_iam_attributes* attributes, CborValue* parameters);

static void nc_iam_remove_all_fingerprints_user(struct nc_iam* iam, struct nc_iam_user* user);
static struct nc_iam_role* nc_iam_find_role_by_name(struct nc_iam* iam, const char* name);

void nc_iam_init(struct nc_iam* iam)
{
    iam->version = 0;
    iam->changeCallback = NULL;
    iam->changeCallbackUserData = NULL;
    nc_iam_list_init(&iam->fingerprints);
    nc_iam_list_init(&iam->users);
    nc_iam_list_init(&iam->roles);
    nc_iam_list_init(&iam->policies);
    iam->defaultRole = NULL;


}

void nc_iam_deinit(struct nc_iam* iam)
{
    if (iam->changeCallback) {
        iam->changeCallback(NABTO_EC_STOPPED, iam->changeCallbackUserData);
        iam->changeCallback = NULL;
    }
}

np_error_code nc_iam_set_change_callback(struct nc_iam* iam, nc_iam_change_callback changeCallback, void* userData)
{
    if (iam->changeCallback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    iam->changeCallback = changeCallback;
    iam->changeCallbackUserData = userData;
    return NABTO_EC_OK;
}

void nc_iam_updated(struct nc_iam* iam)
{
    iam->version++;
    if (iam->changeCallback) {
        iam->changeCallback(NABTO_EC_OK, iam->changeCallbackUserData);
        iam->changeCallback = NULL;
    }
}


struct nc_iam_user* nc_iam_find_user_by_fingerprint(struct nc_iam* iam, const uint8_t fingerprint[16])
{
    struct nc_iam_list_entry* iterator = iam->fingerprints.sentinel.next;
    while (iterator != &iam->fingerprints.sentinel) {
        struct nc_iam_fingerprint* item = iterator->item;
        if (memcmp(item->fingerprint, fingerprint, 16) == 0) {
            return item->user;
        }
        iterator = iterator->next;
    }
    return NULL;
}

struct nc_iam_role* nc_iam_get_default_role(struct nc_iam* iam)
{
    return iam->defaultRole;
}


np_error_code nc_iam_load_attributes_from_cbor(struct nc_iam_attributes* attributes, void* attributesCbor, size_t attributesCborLength)
{
    np_error_code ec;
    CborParser parser;
    CborValue root;
    CborValue mapEntry;
    cbor_parser_init(attributesCbor, attributesCborLength, 0, &parser, &root);

    cbor_value_enter_container(&root,&mapEntry);
    while(!cbor_value_at_end(&mapEntry)) {
        char name[NC_IAM_MAX_STRING_LENGTH];
        char valueString[NC_IAM_MAX_STRING_LENGTH];
        int64_t valueNumber;

        ec = nc_iam_cbor_get_string(&mapEntry, name, NC_IAM_MAX_STRING_LENGTH);
        if (ec != NABTO_EC_OK) {
            return ec;
        }
        cbor_value_advance(&mapEntry);
        ec = nc_iam_cbor_get_string(&mapEntry, valueString, NC_IAM_MAX_STRING_LENGTH);
        if (ec == NABTO_EC_OK) {
            ec = nc_iam_attributes_add_string(attributes, name, valueString);
            if (ec != NABTO_EC_OK) {
                return ec;
            }
        } else if (cbor_value_is_integer(&mapEntry) && (cbor_value_get_int64(&mapEntry, &valueNumber) == CborNoError)) {
            ec = nc_iam_attributes_add_number(attributes, name, valueNumber);
            if (ec != NABTO_EC_OK) {
                return ec;
            }
        } else {
            return NABTO_EC_IAM_INVALID_ATTRIBUTES;
        }
        cbor_value_advance(&mapEntry);
    }
    cbor_value_leave_container(&root,&mapEntry);
    return NABTO_EC_OK;
}

np_error_code nc_iam_attributes_add_string(struct nc_iam_attributes* attributes, const char* name, const char* value)
{
    if (strlen(name) >= NC_IAM_MAX_STRING_LENGTH || strlen(value) >= NC_IAM_MAX_STRING_LENGTH) {
        return NABTO_EC_IAM_STRING_TOO_LONG;
    }
    if (attributes->used >= NC_IAM_MAX_ATTRIBUTES)
    {
        return NABTO_EC_IAM_TOO_MANY_ATTRIBUTES;
    }
    struct nc_iam_attribute* attribute = &attributes->attributes[attributes->used];
    attribute->value.type = NC_IAM_VALUE_TYPE_STRING;
    strcpy(attribute->name, name);
    strcpy(attribute->value.data.string, value);
    attributes->used += 1;
    return NABTO_EC_OK;
}

np_error_code nc_iam_attributes_add_number(struct nc_iam_attributes* attributes, const char* name, int64_t number)
{
    if (strlen(name) >= NC_IAM_MAX_STRING_LENGTH) {
        return NABTO_EC_IAM_STRING_TOO_LONG;
    }
    if (attributes->used >= NC_IAM_MAX_ATTRIBUTES)
    {
        return NABTO_EC_IAM_TOO_MANY_ATTRIBUTES;
    }
    struct nc_iam_attribute* attribute = &attributes->attributes[attributes->used];
    attribute->value.type = NC_IAM_VALUE_TYPE_NUMBER;
    strcpy(attribute->name, name);
    attribute->value.data.number = number;
    attributes->used += 1;
    return NABTO_EC_OK;
}

np_error_code nc_iam_check_access(struct nc_client_connection* connection, const char* action, void* attributesCbor, size_t attributesCborLength)
{
    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    np_error_code ec;

    if (attributesCbor != NULL && attributesCborLength > 0) {
        ec = nc_iam_load_attributes_from_cbor(&attributes, attributesCbor, attributesCborLength);
        if (ec != NABTO_EC_OK) {
            return ec;
        }
    }
    return nc_iam_check_access_attributes(connection, action, &attributes);
}

np_error_code nc_iam_check_access_attributes(struct nc_client_connection* connection, const char* action, struct nc_iam_attributes* attributes)
{
    if (connection == NULL) {
        return NABTO_EC_FAILED;
    }

    struct nc_iam_user* user = connection->user;
    bool granted = false;
    if (user != NULL) {
        nc_iam_attributes_add_string(attributes, "Connection:UserId", connection->user->id);

        struct nc_iam_list_entry* roleIterator = user->roles.sentinel.next;
        while(roleIterator != &user->roles.sentinel) {
            struct nc_iam_role* role = (struct nc_iam_role*)roleIterator->item;
            struct nc_iam_list_entry* policyIterator = role->policies.sentinel.next;
            while(policyIterator != & role->policies.sentinel) {
                struct nc_iam_policy* policy = (struct nc_iam_policy*)policyIterator->item;
                enum nc_iam_evaluation_result result = nc_iam_evaluate_policy(attributes, action, policy);
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
    } else {
        // user == NULL
        // use the default role
        struct nc_iam_role* role = nc_iam_get_default_role(&connection->device->iam);
        struct nc_iam_list_entry* policyIterator = role->policies.sentinel.next;
        while(policyIterator != & role->policies.sentinel) {
            struct nc_iam_policy* policy = (struct nc_iam_policy*)policyIterator->item;
            enum nc_iam_evaluation_result result = nc_iam_evaluate_policy(attributes, action, policy);
            if (result == NC_IAM_EVALUATION_RESULT_NONE) {
                // no change
            } else if (result == NC_IAM_EVALUATION_RESULT_ALLOW) {
                granted = true;
            } else if (result == NC_IAM_EVALUATION_RESULT_DENY) {
                granted = false;
            }
            policyIterator = policyIterator->next;
        }
    }
    if (granted) {
        return NABTO_EC_OK;
    }
    return NABTO_EC_IAM_DENY;
}

enum nc_iam_evaluation_result nc_iam_evaluate_policy(struct nc_iam_attributes* attributes, const char* action, struct nc_iam_policy* policy)
{
    CborParser parser;
    CborValue map;
    CborValue version;
    CborValue statements;

    cbor_parser_init(policy->cbor, policy->cborLength, 0, &parser, &map);

    cbor_value_map_find_value(&map, "Version", &version);
    int v;
    if (!cbor_value_is_integer(&version) ||
        (cbor_value_get_int(&version, &v) != CborNoError) ||
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
        enum nc_iam_evaluation_result result = nc_iam_evaluate_statement(attributes, action, &statement);
        if (result != NC_IAM_EVALUATION_RESULT_NONE) {
            currentResult = result;
        }
        cbor_value_advance(&statement);
    }

    return currentResult;
}

enum nc_iam_evaluation_result nc_iam_evaluate_statement(struct nc_iam_attributes* attributes, const char* actionStr, CborValue* statement)
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
        !cbor_value_is_boolean(&allow))
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
        cbor_value_advance(&action);
        if (result == true) {
            found = true;
            break;
        }
    }

    np_error_code conditionsOk = nc_iam_check_conditions(attributes, &conditions);
    if (found && conditionsOk == NABTO_EC_OK) {

        if (allowAction) {
            return NC_IAM_EVALUATION_RESULT_ALLOW;
        } else {
            return NC_IAM_EVALUATION_RESULT_DENY;
        }
    }
    return NC_IAM_EVALUATION_RESULT_NONE;
}

np_error_code nc_iam_check_conditions(struct nc_iam_attributes* attributes, CborValue* conditions)
{
    if (!cbor_value_is_valid(conditions)) {
        return NABTO_EC_OK;
    }
    if (!cbor_value_is_array(conditions))
    {
        // conditions must be nonexisting or an array.
        return NABTO_EC_IAM_INVALID_CONDITIONS;
    }

    CborValue condition;
    cbor_value_enter_container(conditions, &condition);
    while(!cbor_value_at_end(&condition))
    {
        np_error_code ec = nc_iam_check_condition(attributes, &condition);
        if (ec != NABTO_EC_OK) {
            return ec;
        }
        cbor_value_advance(&condition);
    }
    cbor_value_leave_container(conditions, &condition);
    return NABTO_EC_OK;
}

np_error_code nc_iam_check_condition(struct nc_iam_attributes* attributes, CborValue* condition)
{
    if (!cbor_value_is_map(condition)) {
        return NABTO_EC_IAM_INVALID_CONDITIONS;
    }

    CborValue stringEqual;
    CborValue numberEqual;
    CborValue attributeEqual;
    cbor_value_map_find_value(condition, "StringEqual", &stringEqual);
    cbor_value_map_find_value(condition, "NumberEqual", &numberEqual);
    cbor_value_map_find_value(condition, "AttributeEqual", &attributeEqual);

    if (cbor_value_is_map(&stringEqual)) {
        return nc_iam_string_equal(attributes, &stringEqual);
    } else if (cbor_value_is_map(&numberEqual)) {
        return nc_iam_number_equal(attributes, &numberEqual);
    } else if (cbor_value_is_map(&attributeEqual)) {
        return nc_iam_attribute_equal(attributes, &attributeEqual);
    }
    return NABTO_EC_IAM_INVALID_CONDITIONS;
}

np_error_code nc_iam_string_equal(struct nc_iam_attributes* attributes, CborValue* parameters)
{
    np_error_code ec;
    char attributeName[33];
    CborValue parameter;
    cbor_value_enter_container(parameters, &parameter);
    ec = nc_iam_cbor_get_string(&parameter, attributeName, 33);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    cbor_value_advance(&parameter);
    if (!cbor_value_is_text_string(&parameter)) {
        return NABTO_EC_NOT_A_STRING;
    }

    struct nc_iam_attribute* attribute = nc_iam_attributes_find_attribute(attributes, attributeName);
    if (!attribute || attribute->value.type != NC_IAM_VALUE_TYPE_STRING) {
        return NABTO_EC_IAM_INVALID_ATTRIBUTES;
    }

    bool matches;
    if (cbor_value_text_string_equals(&parameter, attribute->value.data.string, &matches) && matches) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_FAILED;
    }
}

np_error_code nc_iam_number_equal(struct nc_iam_attributes* attributes, CborValue* parameters)
{
    np_error_code ec;
    char attributeName[33];
    CborValue parameter;
    cbor_value_enter_container(parameters, &parameter);

    ec = nc_iam_cbor_get_string(&parameter, attributeName, 33);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    cbor_value_advance(&parameter);
    if (!cbor_value_is_integer(&parameter)) {
        return NABTO_EC_NOT_A_NUMBER;
    }

    struct nc_iam_attribute* attribute = nc_iam_attributes_find_attribute(attributes, attributeName);
    if (!attribute || attribute->value.type != NC_IAM_VALUE_TYPE_NUMBER) {
        return NABTO_EC_IAM_INVALID_ATTRIBUTES;
    }
    int64_t value;
    if (!cbor_value_is_integer(&parameter) ||
        (cbor_value_get_int64(&parameter, &value) != CborNoError) ||
        attribute->value.data.number != value)
    {
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

np_error_code nc_iam_attribute_equal(struct nc_iam_attributes* attributes, CborValue* parameters)
{
    np_error_code ec;
    char attributeName1[33];
    char attributeName2[33];
    CborValue parameter;
    cbor_value_enter_container(parameters, &parameter);
    ec = nc_iam_cbor_get_string(&parameter, attributeName1, 33);
    if (ec != NABTO_EC_OK) {
        return NABTO_EC_NOT_A_STRING;
    }
    cbor_value_advance(&parameter);
    ec = nc_iam_cbor_get_string(&parameter, attributeName2, 33);
    if (ec != NABTO_EC_OK) {
        return NABTO_EC_NOT_A_STRING;
    }

    struct nc_iam_attribute* attribute1 = nc_iam_attributes_find_attribute(attributes, attributeName1);
    struct nc_iam_attribute* attribute2 = nc_iam_attributes_find_attribute(attributes, attributeName2);
    if (!attribute1 || !attribute2) {
        return NABTO_EC_IAM_INVALID_ATTRIBUTES;
    }

    bool result = false;
    if (attribute1->value.type == NC_IAM_VALUE_TYPE_NUMBER && attribute2->value.type == NC_IAM_VALUE_TYPE_NUMBER) {
        result = (attribute1->value.data.number == attribute2->value.data.number);
    } else if (attribute1->value.type == NC_IAM_VALUE_TYPE_STRING && attribute2->value.type == NC_IAM_VALUE_TYPE_STRING) {
        result = (strcmp(attribute1->value.data.string, attribute2->value.data.string) == 0);
    }

    if (result) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_FAILED;
    }
}

struct nc_iam_attribute* nc_iam_attributes_find_attribute(struct nc_iam_attributes* attributes, const char* attributeName)
{
    size_t i;
    for (i = 0; i < attributes->used; i++) {
        struct nc_iam_attribute* attribute = &attributes->attributes[i];
        if (strcmp(attribute->name, attributeName) == 0) {
            return attribute;
        }
    }
    return NULL;
}

np_error_code nc_iam_set_default_role(struct nc_iam* iam, const char* name)
{
    struct nc_iam_role* role = nc_iam_find_role_by_name(iam, name);
    if (!role) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    iam->defaultRole = role;
    nc_iam_updated(iam);
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
    np_error_code ec;
    struct nc_iam_role* r = nc_iam_find_role_by_name(iam, name);
    if (r) {
        return NABTO_EC_RESOURCE_EXISTS;
    }
    r = calloc(1, sizeof(struct nc_iam_role));
    ec = nc_iam_str_cpy(r->name, name);
    if (ec != NABTO_EC_OK) {
        free(r);
        return ec;
    }
    nc_iam_list_init(&r->policies);
    nc_iam_list_insert(&iam->roles, r);
    nc_iam_updated(iam);
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
    np_error_code ec;
    struct nc_iam_user* existing = nc_iam_find_user_by_name(iam, name);
    if (existing) {
        return NABTO_EC_RESOURCE_EXISTS;
    }

    struct nc_iam_user* user = calloc(1, sizeof(struct nc_iam_user));
    ec = nc_iam_str_cpy(user->id, name);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    nc_iam_list_init(&user->roles);
    nc_iam_list_insert(&iam->users, user);
    nc_iam_updated(iam);
    return NABTO_EC_OK;
}

void nc_iam_remove_all_fingerprints_user(struct nc_iam* iam, struct nc_iam_user* user)
{
    struct nc_iam_list_entry* iterator = iam->fingerprints.sentinel.next;
    while (iterator != &iam->fingerprints.sentinel) {
        struct nc_iam_fingerprint* fp = iterator->item;
        struct nc_iam_list_entry* current = iterator;
        iterator = iterator->next;

        free(fp);
        nc_iam_list_remove(current);
    }
}

np_error_code nc_iam_delete_user(struct nc_device_context* device, const char* name)
{
    struct nc_iam_user* user = nc_iam_find_user_by_name(&device->iam, name);
    if (!user) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }

    // check that user is not used by a connection
    if (nc_device_user_in_use(device, user)) {
        return NABTO_EC_IN_USE;
    }

    // remove all fingerprints the user has
    nc_iam_remove_all_fingerprints_user(&device->iam, user);

    // remove the user
    nc_iam_list_remove_item(&device->iam.users, user);
    free(user);
    return NABTO_EC_OK;
}

np_error_code nc_iam_list_users(struct nc_iam* iam, void* cborBuffer, size_t cborBufferLength, size_t* used)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, cborBuffer, cborBufferLength, 0);
    CborEncoder array;
    cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);

    struct nc_iam_list_entry* iterator = iam->users.sentinel.next;
    while(iterator != &iam->users.sentinel) {
        struct nc_iam_user* user = iterator->item;

        cbor_encode_text_stringz(&array, user->id);
        iterator = iterator->next;
    }
    cbor_encoder_close_container(&encoder, &array);
    size_t extra = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (extra != 0) {
        *used = cborBufferLength + extra;
        return NABTO_EC_OUT_OF_MEMORY;
    } else {
        *used = cbor_encoder_get_buffer_size(&encoder, cborBuffer);
    }
    return NABTO_EC_OK;
}

np_error_code nc_iam_user_get(struct nc_iam* iam, const char* name, void* cborBuffer, size_t cborBufferLength, size_t* used)
{
    struct nc_iam_user* user = nc_iam_find_user_by_name(iam, name);
    if (!user) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    CborEncoder encoder;
    cbor_encoder_init(&encoder, cborBuffer, cborBufferLength, 0);

    nc_iam_dump_user(iam, user, &encoder);

    size_t extra = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (extra != 0) {
        *used = cborBufferLength + extra;
        return NABTO_EC_OUT_OF_MEMORY;
    } else {
        *used = cbor_encoder_get_buffer_size(&encoder, cborBuffer);
    }
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
    nc_iam_updated(iam);
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
    nc_iam_updated(iam);
    return NABTO_EC_OK;
}



np_error_code nc_iam_user_add_fingerprint(struct nc_iam* iam, const char* user, const char* fingerprintHex)
{
    uint8_t fingerprint[16];

    if (!nc_iam_hex_to_data(fingerprintHex, fingerprint, 16)) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    struct nc_iam_user* u = nc_iam_find_user_by_name(iam, user);
    struct nc_iam_user* u2 = nc_iam_find_user_by_fingerprint(iam, fingerprint);
    if (!u) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }
    if (u2 && u != u2) {
        return NABTO_EC_RESOURCE_EXISTS;
    }
    if (u2 == u) {
        return NABTO_EC_OK;
    }
    struct nc_iam_fingerprint* fp = calloc(1, sizeof(struct nc_iam_fingerprint));
    fp->user = u;
    memcpy(fp->fingerprint, fingerprint, 16);
    nc_iam_list_insert(&iam->fingerprints, fp);
    nc_iam_updated(iam);
    return NABTO_EC_OK;
}

np_error_code nc_iam_user_remove_fingerprint(struct nc_iam* iam, const char* user, const char* fingerprintHex)
{
    uint8_t fingerprint[16];

    if (!nc_iam_hex_to_data(fingerprintHex, fingerprint, 16)) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    // TODO
    return NABTO_EC_FAILED;
}


np_error_code nc_iam_role_add_policy(struct nc_iam* iam, const char* role, const char* policy)
{
    struct nc_iam_role* r = nc_iam_find_role_by_name(iam, role);
    struct nc_iam_policy* p = nc_iam_find_policy_by_name(iam, policy);
    if (!r || !p) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    }

    nc_iam_list_insert(&r->policies, p);
    nc_iam_updated(iam);
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
    nc_iam_updated(iam);
    return NABTO_EC_OK;
}

np_error_code nc_iam_str_cpy(char* dst, const char* src)
{
    if (strlen(src) >= NC_IAM_MAX_STRING_LENGTH) {
        return NABTO_EC_IAM_STRING_TOO_LONG;
    }
    strcpy(dst, src);
    return NABTO_EC_OK;
}
