#include "nc_iam.h"
#include "nc_iam_policy.h"

#include "nc_device.h"
#include "nc_coap_server.h"

#include <cbor.h>

#include <string.h>
#include <stdlib.h>

struct nc_iam_user* nc_iam_find_user_by_fingerprint(struct nc_iam* iam, uint8_t fingerprint[16])
{
    return iam->defaultUser;
}

bool nc_iam_check_access(struct nc_iam_env* env, const char* action)
{
    // add "connection:UserId"
    // add "system:UserCount"

    nc_iam_attributes_add_string(env, "connection:UserId", env->connection->user->id);
    nc_iam_attributes_add_number(env, "system:UserCount", nc_iam_get_user_count(env->iam));

    return false;
}


void nc_iam_env_init_coap(struct nc_iam_env* env, struct nc_device_context* device, struct nabto_coap_server_request* request)
{
    env->iam = &device->iam;
    env->connection = nc_coap_server_get_connection(&device->coap, request);
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
