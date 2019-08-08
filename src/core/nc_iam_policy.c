#include "nc_iam_policy.h"
#include "nc_device.h"

#include <cbor.h>
#include <stdlib.h>

static np_error_code nc_iam_cbor_validate_policy(struct nc_iam* iam, const void* cbor, size_t cborLength);

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


np_error_code nc_iam_policy_delete(struct nc_iam* iam, const char* policy)
{
    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nc_iam_policy* p = iterator->item;
        if (strcmp(p->name, policy) == 0) {
            nc_iam_list_remove(iterator);
            nc_iam_policy_free(p);
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
    np_error_code ec;
    ec = nc_iam_cbor_validate_policy(iam, cbor, cborLength);
    if (ec) {
        return ec;
    }

    struct nc_iam_policy* p = nc_iam_find_policy_by_name(iam, name);
    if (!p) {
        p = nc_iam_policy_new(iam, name);
    }
    nc_iam_policy_set_cbor(p, cbor, cborLength);
    nc_iam_updated(iam);
    return NABTO_EC_OK;
}

np_error_code nc_iam_policy_get(struct nc_iam* iam, const char* name, void* buffer, size_t bufferLength, size_t* used)
{
    struct nc_iam_policy* p = nc_iam_find_policy_by_name(iam, name);
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

np_error_code nc_iam_cbor_validate_condition_value(CborValue* value)
{
    if (cbor_value_is_text_string(value) || cbor_value_is_unsigned_integer(value)) {
        return NABTO_EC_OK;
    }

    return NABTO_EC_IAM_INVALID_CONDITIONS;
}

np_error_code nc_iam_cbor_validate_predicate_type(CborValue* predicate, const char* type)
{
    CborValue found;
    cbor_value_map_find_value(predicate, type, &found);
    if (!cbor_value_is_valid(&found)) {
        return NABTO_EC_IAM_INVALID_CONDITIONS;
    }
    return nc_iam_cbor_validate_condition_value(&found);
}

np_error_code nc_iam_cbor_validate_predicate(CborValue* predicate)
{
    if (!cbor_value_is_map(predicate)) {
        return NABTO_EC_IAM_INVALID_PREDICATES;
    }

    // just one needs to be ok
    if (nc_iam_cbor_validate_predicate_type(predicate, "StringEqual") == NABTO_EC_OK ||
        nc_iam_cbor_validate_predicate_type(predicate, "NumberEqual") == NABTO_EC_OK ||
        nc_iam_cbor_validate_predicate_type(predicate, "AttributeEqual") == NABTO_EC_OK )
    {
        return NABTO_EC_OK;
    }

    return NABTO_EC_IAM_INVALID_PREDICATES;
}

np_error_code nc_iam_cbor_validate_condition(CborValue* conditions)
{
    np_error_code ec;
    if (!cbor_value_is_array(conditions)) {
        return NABTO_EC_IAM_INVALID_CONDITIONS;
    }
    CborValue it;
    cbor_value_enter_container(conditions, &it);

    while (!cbor_value_at_end(&it)) {
        ec = nc_iam_cbor_validate_predicate(&it);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&it);
    }
    return NABTO_EC_OK;
}

np_error_code nc_iam_cbor_validate_actions(CborValue* actions)
{
    CborValue it;
    cbor_value_enter_container(actions, &it);
    while (!cbor_value_at_end(&it)) {
        if (!cbor_value_is_text_string(&it)) {
            return NABTO_EC_IAM_INVALID_ACTIONS;
        }
        cbor_value_advance(&it);
    }
    cbor_value_leave_container(actions, &it);
    return NABTO_EC_OK;
}

np_error_code nc_iam_cbor_validate_statement(CborValue* statement)
{
    np_error_code ec;
    if (!cbor_value_is_map(statement)) {
        return NABTO_EC_IAM_INVALID_STATEMENTS;
    }
    CborValue allow;
    CborValue action;
    CborValue condition;

    cbor_value_map_find_value(statement, "Allow", &allow);
    cbor_value_map_find_value(statement, "Actions", &action);
    cbor_value_map_find_value(statement, "Conditions", &condition);

    if (!cbor_value_is_array(&action)) {
        return NABTO_EC_IAM_INVALID_STATEMENTS;
    }

    ec = nc_iam_cbor_validate_actions(&action);
    if (ec) {
        return ec;
    }

    if (!cbor_value_is_boolean(&allow)) {
        return NABTO_EC_IAM_INVALID_STATEMENTS;
    }


    return NABTO_EC_OK;
}



np_error_code nc_iam_cbor_validate_policy(struct nc_iam* iam, const void* cbor, size_t cborLength)
{
    np_error_code ec;
    CborParser parser;
    CborValue map;

    cbor_parser_init(cbor, cborLength, 0, &parser, &map);

    if (!cbor_value_is_map(&map)) {
        return NABTO_EC_IAM_INVALID_POLICIES;
    }

    CborValue version;
    CborValue statements;

    cbor_value_map_find_value(&map, "Version", &version);
    cbor_value_map_find_value(&map, "Statements", &statements);

    if (!cbor_value_is_integer(&version)) {
        return NABTO_EC_IAM_INVALID_POLICIES;
    }

    if (!cbor_value_is_array(&statements)) {
        return NABTO_EC_IAM_INVALID_POLICIES;
    }

    CborValue statement;
    cbor_value_enter_container(&statements, &statement);
    while (!cbor_value_at_end(&statement)) {
        ec = nc_iam_cbor_validate_statement(&statement);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&statement);
    }
    cbor_value_leave_container(&statements, &statement);

    return NABTO_EC_OK;
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
