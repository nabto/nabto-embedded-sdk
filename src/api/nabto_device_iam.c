#include "nabto_device_iam.h"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include "nabto_device_defines.h"
#include "nabto_device_coap.h"

#include <stdlib.h>

struct nabto_device_iam_env* nabto_device_iam_env_new_internal()
{
    return calloc(1, sizeof(struct nabto_device_iam_env));
}

void nabto_device_iam_env_free_internal(struct nabto_device_iam_env* env)
{
    free(env);
}

NabtoDeviceIamEnv* NABTO_DEVICE_API nabto_device_iam_env_from_coap_request(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    NabtoDeviceIamEnv* env = NULL;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);

    // TODO

    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return env;
}

void nabto_device_iam_env_free(NabtoDeviceIamEnv* e)
{
    struct nabto_device_iam_env* env = (struct nabto_device_iam_env*) e;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_iam_check_action(NabtoDeviceIamEnv* env, const char* action)
{
    NabtoDeviceError ec = NABTO_DEVICE_EC_IAM_DENY;
    struct nabto_device_iam_env* iamEnv = (struct nabto_device_iam_env*) env;

    struct nabto_device_context* dev = iamEnv->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    // get the user
    // get the attributes

    if (nm_iam_has_access_to_action(&device->iam, user, attributes, nm_iam_get_action(&device->iam, action))) {
        ec = NABTO_DEVICE_EC_OK;
    }
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return ec;
}
