#include "nc_iam_dump.h"
#include "nc_iam_policy.h"
#include "nc_iam_cbor.h"

#include <cbor.h>
#include <cbor_extra.h>

np_error_code nc_iam_load_policies(struct nc_iam* iam, CborValue* policies);
np_error_code nc_iam_load_roles(struct nc_iam* iam, CborValue* roles);
np_error_code nc_iam_load_users(struct nc_iam* iam, CborValue* users);
np_error_code nc_iam_load_default_role(struct nc_iam* iam, CborValue* defaultRole);

np_error_code nc_iam_load(struct nc_iam* iam, void* cbor, size_t cborLength)
{
    CborParser parser;
    CborValue map;
    np_error_code ec;
    cbor_parser_init(cbor, cborLength, 0, &parser, &map);


    CborValue policies;
    // map with users, roles and policies
    if (!cbor_value_is_map(&map)) {
        return false;
    }

    cbor_value_map_find_value(&map, "Policies", &policies);
    ec = nc_iam_load_policies(iam, &policies);
    if (ec) {
        return ec;
    }

    CborValue roles;
    cbor_value_map_find_value(&map, "Roles", &roles);
    ec = nc_iam_load_roles(iam, &roles);
    if (ec) {
        return ec;
    }

    CborValue users;
    cbor_value_map_find_value(&map, "Users", &users);
    ec = nc_iam_load_users(iam, &users);
    if (ec) {
        return ec;
    }

    CborValue defaultRole;
    cbor_value_map_find_value(&map, "DefaultRole", &defaultRole);
    ec = nc_iam_load_default_role(iam, &defaultRole);
    if (ec) {
        return ec;
    }



    return NABTO_EC_OK;
}


np_error_code nc_iam_load_policies(struct nc_iam* iam, CborValue* policies)
{
    np_error_code ec;
    if (!cbor_value_is_map(policies)) {
        return NABTO_EC_IAM_INVALID_POLICIES;
    }

    CborValue policy;
    cbor_value_enter_container(policies, &policy);

    while (!cbor_value_at_end(&policy)) {
        char buffer[33];
        ec = nc_iam_cbor_get_string(&policy, buffer, 33);
        if (ec) {
            return ec;
        }

        cbor_value_advance(&policy);
        const uint8_t* start = cbor_value_get_next_byte(&policy);
        cbor_value_advance(&policy);
        const uint8_t* end = cbor_value_get_next_byte(&policy);

        size_t policyLength = end - start;

        ec = nc_iam_cbor_policy_create(iam, buffer, start, policyLength);
        if (ec) {
            return ec;
        }
    }

    cbor_value_leave_container(policies, &policy);
    return NABTO_EC_OK;
}

np_error_code nc_iam_load_role(struct nc_iam* iam, const char* roleName, CborValue* role)
{
    np_error_code ec;
    nc_iam_create_role(iam, roleName);
    if (!cbor_value_is_array(role)) {
        return NABTO_EC_IAM_INVALID_ROLES;
    }
    CborValue policyName;
    cbor_value_enter_container(role, &policyName);
    while(!cbor_value_at_end(&policyName)) {
        char buffer[33];
        ec = nc_iam_cbor_get_string(&policyName, buffer, 33);
        if (ec) {
            return ec;
        }
        ec = nc_iam_role_add_policy(iam, roleName, buffer);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&policyName);
    }
    cbor_value_leave_container(role, &policyName);
    return NABTO_EC_OK;
}

np_error_code nc_iam_load_roles(struct nc_iam* iam, CborValue* roles)
{
    np_error_code ec;
    if (!cbor_value_is_map(roles)) {
        return NABTO_EC_IAM_INVALID_ROLES;
    }

    CborValue role;
    cbor_value_enter_container(roles, &role);
    while(!cbor_value_at_end(&role)) {
        char buffer[33];
        ec = nc_iam_cbor_get_string(&role, buffer, 33);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&role);

        ec = nc_iam_load_role(iam, buffer, &role);
        if (ec) {
            return ec;
        }
    }
    cbor_value_leave_container(roles, &role);
    return NABTO_EC_OK;
}



np_error_code nc_iam_load_user(struct nc_iam* iam, const char* userName, CborValue* user)
{
    np_error_code ec;
    nc_iam_create_user(iam, userName);
    if (!cbor_value_is_map(user)) {
        return NABTO_EC_IAM_INVALID_USERS;
    }

    CborValue roles;
    cbor_value_map_find_value(user, "Roles", &roles);
    if (!cbor_value_is_array(&roles)) {
        return NABTO_EC_IAM_INVALID_USERS;
    }

    CborValue role;
    cbor_value_enter_container(&roles, &role);

    while(!cbor_value_at_end(&role)) {
        char roleName[33];
        ec = nc_iam_cbor_get_string(&role, roleName, 33);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&role);
        ec = nc_iam_user_add_role(iam, userName, roleName);
        if (ec) {
            return ec;
        }

    }

    CborValue fingerprints;
    cbor_value_map_find_value(user, "Fingerprints", &fingerprints);
    if (!cbor_value_is_array(&fingerprints)) {
        return NABTO_EC_IAM_INVALID_USERS;
    }

    CborValue fingerprint;
    cbor_value_enter_container(&fingerprints, &fingerprint);

    while(!cbor_value_at_end(&fingerprint)) {
        char fpHex[33];
        ec = nc_iam_cbor_get_string(&fingerprint, fpHex, 33);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&fingerprint);
        ec = nc_iam_user_add_fingerprint(iam, userName, fpHex);
        if (ec) {
            return ec;
        }
    }

    cbor_value_leave_container(&fingerprints, &fingerprint);
    return NABTO_EC_OK;
}

np_error_code nc_iam_load_users(struct nc_iam* iam, CborValue* users)
{
    np_error_code ec;
    if (!cbor_value_is_map(users)) {
        return NABTO_EC_IAM_INVALID_USERS;
    }
    CborValue user;
    cbor_value_enter_container(users, &user);
    while(!cbor_value_at_end(&user)) {
        char userName[33];
        ec = nc_iam_cbor_get_string(&user, userName, 33);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&user);
        ec = nc_iam_load_user(iam, userName, &user);
        if (ec) {
            return ec;
        }
        cbor_value_advance(&user);

    }
    cbor_value_leave_container(users, &user);
    return NABTO_EC_OK;
}

np_error_code nc_iam_load_default_role(struct nc_iam* iam, CborValue* defaultRole)
{
    np_error_code ec;
    char buffer[33];
    ec = nc_iam_cbor_get_string(defaultRole, buffer, 33);
    if (ec) {
        return ec;
    }
    return nc_iam_set_default_role(iam, buffer);
}
