#include "nc_iam.h"

#include "nc_device.h"
#include "nc_coap_server.h"

#include <string.h>
#include <stdlib.h>

struct nc_iam_user* nc_iam_find_user(struct nc_iam* iam, uint8_t fingerprint[16])
{
    return iam->defaultUser;
}

bool nc_iam_check_access(struct nc_iam_env* env, const char* action)
{
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
