#include "nabto_device_iam.h"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include "nabto_device_defines.h"
#include "nabto_device_coap.h"
#include <core/nc_iam_policy.h>
#include <core/nc_iam.h>
#include <core/nc_iam_dump.h>

#include <stdlib.h>

struct nabto_device_iam_env* nabto_device_iam_env_new_internal()
{
    return calloc(1, sizeof(struct nabto_device_iam_env));
}

void nabto_device_iam_env_free_internal(struct nabto_device_iam_env* env)
{
    free(env);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_dump(NabtoDevice* device, uint64_t* version, void* buffer, size_t bufferLength, size_t* used)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_dump(&dev->core.iam, version, buffer, bufferLength, used);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

// Load iam state from a cbor file.
NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_load(NabtoDevice* device, void* cbor, size_t cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_load(&dev->core.iam, cbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceIamEnv* NABTO_DEVICE_API nabto_device_iam_env_from_coap_request(NabtoDeviceCoapRequest* request)
{
    /* struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request; */
    /* NabtoDeviceIamEnv* env = NULL; */
    /* nabto_device_threads_mutex_lock(req->dev->eventMutex); */

    /* // TODO */

    /* nabto_device_threads_mutex_unlock(req->dev->eventMutex); */
    /* return env; */
    return NULL;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_env_add_attribute_number(NabtoDeviceIamEnv* env, const char* name, uint32_t value)
{
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}

void nabto_device_iam_env_free(NabtoDeviceIamEnv* e)
{
//    struct nabto_device_iam_env* env = (struct nabto_device_iam_env*) e;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_iam_check_action(NabtoDeviceIamEnv* env, const char* action)
{
    /* NabtoDeviceError ec = NABTO_DEVICE_EC_IAM_DENY; */
    /* struct nabto_device_iam_env* iamEnv = (struct nabto_device_iam_env*) env; */

    /* struct nabto_device_context* dev = iamEnv->device; */
    /* nabto_device_threads_mutex_lock(dev->eventMutex); */
    /* // get the user */
    /* // get the attributes */

    /* if (nm_iam_has_access_to_action(&device->iam, user, attributes, nm_iam_get_action(&device->iam, action))) { */
    /*     ec = NABTO_DEVICE_EC_OK; */
    /* } */
    /* nabto_device_threads_mutex_unlock(req->dev->eventMutex); */
    /* return ec; */
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}



NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_set_default_user(NabtoDevice* device, const char* user)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_set_default_user(&dev->core.iam, user);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

// add a user to the iam system
NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_create(NabtoDevice* device, const char* user)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    // TODO check return value
    nc_iam_create_user(&dev->core.iam, user);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_delete(NabtoDevice* device, const char* user);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_get(NabtoDevice* device, const char* user, void** cbor, size_t* cborLength);


NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_list(NabtoDevice* device, void** cbor, size_t* cborLength);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_add_role(NabtoDevice* device, const char* user, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_user_add_role(&dev->core.iam, user, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_role(NabtoDevice* device, const char* user, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_user_remove_role(&dev->core.iam, user, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);

}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_add_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_list(NabtoDevice* device, void** cbor, size_t* cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_list_roles(&dev->core.iam, cbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_get(NabtoDevice* device, const char* role, void** cbor, size_t* cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_role_get(&dev->core.iam, role, cbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_create(NabtoDevice* device, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_create_role(&dev->core.iam, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_delete(NabtoDevice* device, const char* role)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_delete_role(&dev->core.iam, role);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_add_policy(NabtoDevice* device, const char* role, const char* policy)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_role_add_policy(&dev->core.iam, role, policy);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_deivce_iam_roles_remove_policy(NabtoDevice* device, const char* role, const char* policy)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_role_remove_policy(&dev->core.iam, role, policy);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}


NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_create(NabtoDevice* device, const char* name, void* cbor, size_t cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_iam_cbor_policy_create(&dev->core.iam, name, cbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_delete(NabtoDevice* device, const char* policy)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    // TODO check return value
    nc_iam_policy_delete(&dev->core.iam, policy);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}


NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_get(NabtoDevice* device, const char* policy, void** cbor, size_t* cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    // TODO check return value
    struct nc_iam_policy* p = nc_iam_find_policy(&dev->core.iam, policy);
    if (p == NULL) {
        // TODO policy not found or just not found
        ec = NABTO_DEVICE_EC_FAILED;
    } else {

        *cbor = malloc(p->cborLength);
        memcpy(*cbor, p->cbor, p->cborLength);
        *cborLength = p->cborLength;
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_list(NabtoDevice* device, void** cbor, size_t* cborLength)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nc_iam_list_policies(&dev->core.iam, cbor, cborLength);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}
