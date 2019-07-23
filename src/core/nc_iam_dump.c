#include "nc_iam_dump.h"
#include "nc_iam_policy.h"

#include <cbor.h>
#include <cbor_extra.h>


void nc_iam_dump_users(struct nc_iam* iam, CborEncoder* encoder);
void nc_iam_dump_user(struct nc_iam_user* iam, CborEncoder*);
void nc_iam_dump_roles(struct nc_iam* iam, CborEncoder* encoder);
void nc_iam_dump_policies(struct nc_iam* iam, CborEncoder* encoder);


np_error_code nc_iam_dump(struct nc_iam* iam, uint64_t* version, void* buffer, size_t bufferLength, size_t* used)
{
    *version = iam->version;
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, buffer, bufferLength, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Users");
    nc_iam_dump_users(iam, &map);

    cbor_encode_text_stringz(&map, "Roles");
    nc_iam_dump_roles(iam, &map);

    cbor_encode_text_stringz(&map, "Policies");
    nc_iam_dump_policies(iam, &map);

    CborError ec = cbor_encoder_close_container(&encoder, &map);
    if (ec == CborNoError) {

        *used = cbor_encoder_get_buffer_size(&encoder, buffer);
        return NABTO_EC_OK;
    }

    if (ec == CborErrorOutOfMemory) {
        *used = bufferLength + cbor_encoder_get_extra_bytes_needed(&encoder);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_FAILED;
}


void nc_iam_dump_users(struct nc_iam* iam, CborEncoder* encoder)
{
    CborEncoder users;
    cbor_encoder_create_map(encoder, &users, CborIndefiniteLength);
    struct nc_iam_list_entry* iterator = iam->users.sentinel.next;
    while(iterator != &iam->users.sentinel) {
        struct nc_iam_user* user = iterator->item;

        cbor_encode_text_stringz(&users, user->id);
        nc_iam_dump_user(user, &users);

        iterator = iterator->next;
    }
    cbor_encoder_close_container(encoder, &users);
}

void nc_iam_dump_user(struct nc_iam_user* user, CborEncoder* encoder)
{
    CborEncoder map;

    cbor_encoder_create_map(encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "roles");
    {
        CborEncoder roles;
        cbor_encoder_create_array(&map, &roles, CborIndefiniteLength);
        struct nc_iam_list_entry* iterator = user->roles.sentinel.next;
        while(iterator != &user->roles.sentinel) {
            struct nc_iam_role* role = iterator->item;
            cbor_encode_text_stringz(&roles, role->name);
            iterator = iterator->next;
        }

        cbor_encoder_close_container(&map, &roles);
    }

    cbor_encoder_close_container(encoder, &map);
}

void nc_iam_dump_roles(struct nc_iam* iam, CborEncoder* encoder)
{
    CborEncoder map;
    cbor_encoder_create_map(encoder, &map, CborIndefiniteLength);

    struct nc_iam_list_entry* iterator = iam->roles.sentinel.next;
    while (iterator != &iam->roles.sentinel)
    {
        struct nc_iam_role* role = iterator->item;
        cbor_encode_text_stringz(&map, role->name);
        CborEncoder array;
        cbor_encoder_create_array(&map, &array, CborIndefiniteLength);

        struct nc_iam_list_entry* policyIterator = role->policies.sentinel.next;
        while (policyIterator != &role->policies.sentinel) {
            struct nc_iam_policy* policy = policyIterator->item;
            cbor_encode_text_stringz(&array, policy->name);
            policyIterator = policyIterator->next;
        }

        cbor_encoder_close_container(&map, &array);

        iterator = iterator->next;
    }

    cbor_encoder_close_container(encoder, &map);
}

void nc_iam_dump_policies(struct nc_iam* iam, CborEncoder* encoder)
{
    CborEncoder map;
    cbor_encoder_create_map(encoder, &map, CborIndefiniteLength);
    struct nc_iam_list_entry* iterator = iam->policies.sentinel.next;
    while (iterator != &iam->policies.sentinel)
    {
        struct nc_iam_policy* policy = iterator->item;
        cbor_encode_text_stringz(&map, policy->name);
        cbor_encode_encoded_item(&map, policy->cbor, policy->cborLength);
        iterator = iterator->next;
    }
    cbor_encoder_close_container(encoder, &map);
}




bool nc_iam_load_policies(struct nc_iam* iam, CborValue* policies)
{
    if (!cbor_value_is_map(policies)) {
        return false;
    }

    CborValue policy;
    cbor_value_enter_container(policies, &policy);

    while (!cbor_value_at_end(&policy)) {
        char buffer[33];
        memset(buffer, 0, 33);
        if (!cbor_value_is_text_string(&policy)) {
            return false;
        }

        size_t stringLength;
        if (!cbor_value_calculate_string_length(&policy, &stringLength) || stringLength > 32) {
            return false;
        }

        CborValue next;
        size_t len = 33;
        cbor_value_copy_text_string(&policy, buffer, &len, &next);

        cbor_value_advance(&policy);
        const uint8_t* start = cbor_value_get_next_byte(&policy);
        cbor_value_advance(&policy);
        const uint8_t* end = cbor_value_get_next_byte(&policy);

        size_t policyLength = end - start;

        nc_iam_cbor_policy_create(iam, buffer, start, policyLength);
    }

    cbor_value_leave_container(policies, &policy);
    return true;
}

bool nc_iam_load_role(struct nc_iam* iam, const char* roleName, CborValue* role)
{
    nc_iam_create_role(iam, roleName);
    if (!cbor_value_is_array(role)) {
        return false;
    }
    CborValue policyName;
    cbor_value_enter_container(role, &policyName);
    while(!cbor_value_at_end(&policyName)) {
        char buffer[33];
        memset(buffer, 0, 33);
        if (!cbor_value_is_text_string(&policyName)) {
            return false;
        }
        size_t stringLength;
        if (!cbor_value_calculate_string_length(&policyName, &stringLength) || stringLength > 32) {
            return false;
        }

        size_t len = 33;
        cbor_value_copy_text_string(&policyName, buffer, &len, &policyName);
        nc_iam_role_add_policy(iam, roleName, buffer);
        //cbor_value_advance(&policyName);
    }
    cbor_value_leave_container(role, &policyName);
    return true;
}

bool nc_iam_load_roles(struct nc_iam* iam, CborValue* roles)
{
    if (!cbor_value_is_map(roles)) {
        return false;
    }

    CborValue role;
    cbor_value_enter_container(roles, &role);
    while(!cbor_value_at_end(&role)) {
        char buffer[33];
        memset(buffer, 0, 33);
        if (!cbor_value_is_text_string(&role)) {
            return false;
        }
        size_t stringLength;
        if (!cbor_value_calculate_string_length(&role, &stringLength) || stringLength > 32) {
            return false;
        }
        CborValue next;
        size_t len = 33;
        cbor_value_copy_text_string(&role, buffer, &len, &next);
        cbor_value_advance(&role);

        nc_iam_load_role(iam, buffer, &role);

    }
    cbor_value_leave_container(roles, &role);
    return true;
}



bool nc_iam_load_user(struct nc_iam* iam, const char* userName, CborValue* user)
{
    if (!cbor_value_is_map(user)) {
        return false;
    }

    CborValue roles;
    cbor_value_map_find_value(user, "Roles", &roles);
    if (!cbor_value_is_array(&roles)) {
        return false;
    }

    CborValue role;
    cbor_value_enter_container(&roles, &role);

    while(!cbor_value_at_end(&role)) {
        char roleName[33];
        memset(roleName, 0, 33);
        if (!cbor_value_is_text_string(&role)) {
            return false;
        }
        size_t stringLength;
        if (!cbor_value_calculate_string_length(&role, &stringLength) || stringLength > 32) {
            return false;
        }
        CborValue next;
        size_t len = 33;
        cbor_value_copy_text_string(&role, roleName, &len, &next);
        cbor_value_advance(&role);
        nc_iam_user_add_role(iam, userName, roleName);

    }


    cbor_value_leave_container(&roles, &role);
    return true;
}

bool nc_iam_load_users(struct nc_iam* iam, CborValue* users)
{
    if (!cbor_value_is_map(users)) {
        return false;
    }
    CborValue user;
    cbor_value_enter_container(users, &user);

    cbor_value_leave_container(users, &user);
    return true;
}

np_error_code nc_iam_load(struct nc_iam* iam, void* cbor, size_t cborLength)
{
    CborParser parser;
    CborValue map;
    cbor_parser_init(cbor, cborLength, 0, &parser, &map);


    CborValue policies;
    // map with users, roles and policies
    if (!cbor_value_is_map(&map)) {
        return false;
    }

    cbor_value_map_find_value(&map, "Policies", &policies);
    nc_iam_load_policies(iam, &policies);

    CborValue roles;
    cbor_value_map_find_value(&map, "Roles", &roles);
    nc_iam_load_roles(iam, &roles);



    return NABTO_EC_OK;
}
