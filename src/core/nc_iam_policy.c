#include "nc_iam_policy.h"
#include "nc_device.h"

#include <cbor.h>
#include <stdlib.h>

static bool nc_iam_cbor_validate_policy(struct nc_device_context* context, void* cbor, size_t cborLength);

struct nc_iam_policy* nc_iam_policy_new(struct nc_iam* iam, const char* name)
{
    struct nc_iam_policy* p = calloc(1, sizeof(struct nc_iam_policy));
    p->name = strdup(name);

    nc_iam_list_insert(&iam->policies, p);
    return p;
}

void nc_iam_policy_free(struct nc_iam_policy* p)
{
    free(p->name);
    free(p->cbor);
    free(p);
}

void nc_iam_policy_set_cbor(struct nc_iam_policy* p, void* cbor, size_t cborLength)
{
    free(p->cbor);
    p->cbor = malloc(cborLength);
    memcpy(p->cbor, cbor, cborLength);
    p->cborLength = cborLength;
}

struct nc_iam_policy* nc_iam_find_policy(struct nc_iam* iam, const char* policy)
{
    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        if (strcmp(p->name, policy) == 0) {
            return p;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void nc_iam_policy_delete(struct nc_iam* iam, const char* policy)
{
    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        if (strcmp(p->name, policy) == 0) {
            nc_iam_list_remove(iterator);
            nc_iam_policy_free(p);
            return;
        }
        iterator = iterator->next;
    }
}

void nc_iam_list_policies(struct nc_iam* iam, void** cbor, size_t* cborLength)
{
    uint8_t buffer[1024];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, buffer, 1024, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        cbor_encode_text_stringz(&map, p->name);
        iterator = iterator->next;
    }
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, buffer);
    *cbor = malloc(used);
    memcpy(*cbor, buffer, used);
    *cborLength = used;
    return;
}

np_error_code nc_iam_cbor_policy_create(struct nc_device_context* device, const char* name, void* cbor, size_t cborLength)
{
    struct nc_iam* iam = &device->iam;
    if (!nc_iam_cbor_validate_policy(device, cbor, cborLength)) {
        return NABTO_EC_IAM_INVALID_POLICY;
    }

    struct nc_iam_policy* p = nc_iam_find_policy(iam, name);
    if (!p) {
        p = nc_iam_policy_new(iam, name);
    }
    nc_iam_policy_set_cbor(p, cbor, cborLength);

    return NABTO_EC_OK;
}



/**
 * Format of a policy
{
  "Version": 1,
  "Statement": {
    "Allow": true|false,
    "Action": [ "module:action1", "module:action2" ],
    "Condition": [
      { "StringEqual": { "iam:User", "admin" } },
      { "NumberEqual": { "system:UserCount", 1 } },
      { "StringEqual": { "tcptunnel:Host", { "Attribute": "system:Localhost" } } }
    ]
  }
}
 */

bool nc_iam_cbor_validate_condition_value(CborValue* value)
{
    if (cbor_value_is_text_string(value) || cbor_value_is_unsigned_integer(value)) {
        return true;
    }

    if (cbor_value_is_map(value)) {
        CborValue attribute;
        cbor_value_map_find_value(value, "Attriute", &attribute);
        return cbor_value_is_text_string(&attribute);
    }
    return false;
}

bool nc_iam_cbor_validate_predicate_type(CborValue* predicate, const char* type)
{
    CborValue found;
    cbor_value_map_find_value(predicate, "StringEqual", &found);
    if (!cbor_value_is_valid(&found)) {
        return true;
    }
    return nc_iam_cbor_validate_condition_value(&found);
}

bool nc_iam_cbor_validate_predicate(CborValue* predicate)
{
    if (!cbor_value_is_map(predicate)) {
        return false;
    }

    if (!nc_iam_cbor_validate_predicate_type(predicate, "StringEqual") ||
        !nc_iam_cbor_validate_predicate_type(predicate, "NumberEqual") )
    {
        return false;
    }

    return true;
}

bool nc_iam_cbor_validate_condition(CborValue* conditions)
{
    if (!cbor_value_is_array(conditions)) {
        return false;
    }
    CborValue it;
    cbor_value_enter_container(conditions, &it);

    while (!cbor_value_at_end(&it)) {
        if (!nc_iam_cbor_validate_predicate(&it)) {
            return false;
        }
        cbor_value_advance(&it);
    }
    return true;
}

bool nc_iam_cbor_validate_actions(CborValue* actions)
{
    CborValue it;
    cbor_value_enter_container(actions, &it);
    while (!cbor_value_at_end(&it)) {
        if (!cbor_value_is_text_string(&it)) {
            return false;
        }
        cbor_value_advance(&it);
    }
    cbor_value_leave_container(actions, &it);
    return true;
}

bool nc_iam_cbor_validate_statement(CborValue* statement)
{
    if (!cbor_value_is_map(statement)) {
        return false;
    }
    CborValue effect;
    CborValue action;
    CborValue condition;

    cbor_value_map_find_value(statement, "Effect", &effect);
    cbor_value_map_find_value(statement, "Action", &action);
    cbor_value_map_find_value(statement, "Condition", &condition);

    if (!cbor_value_is_array(&action)) {
        return false;
    }
    if (!nc_iam_cbor_validate_actions(&action)) {
        return false;
    }

    if (!cbor_value_is_boolean(&effect)) {
        return false;
    }


    return true;
}



bool nc_iam_cbor_validate_policy(struct nc_device_context* context, void* cbor, size_t cborLength)
{
    CborParser parser;
    CborValue map;

    cbor_parser_init(cbor, cborLength, 0, &parser, &map);

    if (!cbor_value_is_map(&map)) {
        return false;
    }



    return true;
}


struct nc_iam_policy* nc_iam_find_policy_by_name(struct nc_iam* iam, const char* name)
{
    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        if (strcmp(p->name, name) == 0) {
            return p;
        }
        iterator = iterator->next;
    }
    return NULL;
}
