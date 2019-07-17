#include "nc_iam.h"

#include "nc_device.h"
#include "nc_coap_server.h"

#include <cbor.h>

#include <string.h>
#include <stdlib.h>

struct nc_iam_user* nc_iam_find_user(struct nc_iam* iam, uint8_t fingerprint[16])
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
