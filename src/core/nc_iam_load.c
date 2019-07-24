#include "nc_iam_dump.h"
#include "nc_iam_policy.h"

#include <cbor.h>
#include <cbor_extra.h>

bool nc_iam_load_policies(struct nc_iam* iam, CborValue* policies);
bool nc_iam_load_roles(struct nc_iam* iam, CborValue* roles);
bool nc_iam_load_users(struct nc_iam* iam, CborValue* users);
bool nc_iam_load_default_user(struct nc_iam* iam, CborValue* defaultUser);

bool load_string_identifier(CborValue* value, char* buffer, size_t bufferLength);

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

    CborValue users;
    cbor_value_map_find_value(&map, "Users", &users);
    nc_iam_load_users(iam, &users);

    CborValue defaultUser;
    cbor_value_map_find_value(&map, "DefaultUser", &defaultUser);
    nc_iam_load_default_user(iam, &defaultUser);



    return NABTO_EC_OK;
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
        if (!load_string_identifier(&policy, buffer, 33)) {
            return false;
        }

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
        if (!load_string_identifier(&policyName, buffer, 33)) {
            return false;
        }
        nc_iam_role_add_policy(iam, roleName, buffer);
        cbor_value_advance(&policyName);
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
        if (!load_string_identifier(&role, buffer, 33)) {
            return false;
        }
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
        if (!load_string_identifier(&role, roleName, 33)) {
            return false;
        }
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

bool nc_iam_load_default_user(struct nc_iam* iam, CborValue* defaultUser)
{
    char buffer[33];
    if (cbor_value_is_text_string(defaultUser) && load_string_identifier(defaultUser, buffer, 33)) {
        nc_iam_set_default_user(iam, buffer);
    }
    return true;
}


bool load_string_identifier(CborValue* value, char* buffer, size_t bufferLength)
{
    memset(buffer, 0, 33);
    if (!cbor_value_is_text_string(value)) {
        return false;
    }
    size_t stringLength;
    if (!cbor_value_calculate_string_length(value, &stringLength) || stringLength > (bufferLength - 1)) {
        return false;
    }

    size_t len = bufferLength;
    cbor_value_copy_text_string(value, buffer, &len, NULL);
    return true;
}
