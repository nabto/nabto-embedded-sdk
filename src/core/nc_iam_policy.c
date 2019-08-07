#include "nc_iam_policy.h"
#include "nc_device.h"

#include <cbor.h>
#include <stdlib.h>

static bool nc_iam_cbor_validate_policy(struct nc_iam* iam, const void* cbor, size_t cborLength);

struct nc_iam_policy* nc_iam_policy_new(struct nc_iam* iam, const char* name)
{
    struct nc_iam_policy* p = calloc(1, sizeof(struct nc_iam_policy));
    np_error_code ec;
    ec = nc_iam_str_cpy(p->name, name);
    if (ec != NABTO_EC_OK) {
        free(p);
        return NULL;
    }
    nc_iam_list_insert(&iam->policies, p);
    return p;
}

void nc_iam_policy_free(struct nc_iam_policy* p)
{
    free(p->cbor);
    free(p);
}

void nc_iam_policy_set_cbor(struct nc_iam_policy* p, const void* cbor, size_t cborLength)
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

np_error_code nc_iam_policy_delete(struct nc_iam* iam, const char* policy)
{
    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        if (strcmp(p->name, policy) == 0) {
            nc_iam_list_remove(iterator);
            nc_iam_policy_free(p);
            // TODO return np_error_code
            nc_iam_updated(iam);
            return NABTO_EC_OK;
        }
        iterator = iterator->next;
    }

    return NABTO_EC_NO_SUCH_RESOURCE;
}

np_error_code nc_iam_list_policies(struct nc_iam* iam, void* buffer, size_t bufferLength, size_t* used)
{
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, buffer, bufferLength, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        cbor_encode_text_stringz(&map, p->name);
        iterator = iterator->next;
    }
    cbor_encoder_close_container(&encoder, &map);

    size_t extra = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (extra != 0) {
        *used = bufferLength + extra;
        return NABTO_EC_OUT_OF_MEMORY;
    } else {
        *used = cbor_encoder_get_buffer_size(&encoder, buffer);
    }
    return NABTO_EC_OK;
}

np_error_code nc_iam_cbor_policy_create(struct nc_iam* iam, const char* name, const void* cbor, size_t cborLength)
{
    if (!nc_iam_cbor_validate_policy(iam, cbor, cborLength)) {
        return NABTO_EC_IAM_INVALID_POLICY;
    }

    struct nc_iam_policy* p = nc_iam_find_policy(iam, name);
    if (!p) {
        p = nc_iam_policy_new(iam, name);
    }
    nc_iam_policy_set_cbor(p, cbor, cborLength);
    nc_iam_updated(iam);
    return NABTO_EC_OK;
}

np_error_code nc_iam_policy_get(struct nc_iam* iam, const char* name, void* buffer, size_t bufferLength, size_t* used)
{
    struct nc_iam_policy* p = nc_iam_find_policy(iam, name);
    if (p == NULL) {
        return NABTO_EC_NO_SUCH_RESOURCE;
    } else {
        *used = p->cborLength;
        if (p->cborLength > bufferLength) {
            return NABTO_EC_OUT_OF_MEMORY;
        } else {
            memcpy(buffer, p->cbor, p->cborLength);
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_OK;
}

/**
 * Format of a policy
{
  "Version": 1,
  "Statements": {
    "Allow": true|false,
    "Actions": [ "Module:Action1", "Module:Action2" ],
    "Conditions": [
      { "StringEqual": { "IAM:UserId", "admin" } },
      { "StringEqual": { "TcpTunnel:Host", "localhost" } },
      { "NumberEqual": { "TcpTunnel:Port", 4242 } },
      { "AttributeEqual": { "IAM:UserId", "Connection:UserId" } }
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
        cbor_value_map_find_value(value, "Attribute", &attribute);
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
    cbor_value_map_find_value(statement, "Actions", &action);
    cbor_value_map_find_value(statement, "Conditions", &condition);

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



bool nc_iam_cbor_validate_policy(struct nc_iam* iam, const void* cbor, size_t cborLength)
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
