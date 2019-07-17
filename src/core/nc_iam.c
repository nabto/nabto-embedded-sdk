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
