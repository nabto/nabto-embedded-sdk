#include "nabto_device_iam.h"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include "nabto_device_defines.h"
#include "nabto_device_coap.h"
#include "nabto_device_future.h"
#include "nabto_api_future_queue.h"
#include <modules/iam/nc_iam_policy.h>
#include <modules/iam/nc_iam.h>
#include <modules/iam/nc_iam_dump.h>

#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

np_error_code nc_iam_check_access_function_override_adapter(uint64_t connectionRef,const char* action, void* attributes, size_t attributesLength, void* userData)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)userData;

    NabtoDeviceError ec = dev->checkAccessFunctionOverride(connectionRef, action, attributes, attributesLength, dev->checkAccessFunctionOverrideUserData);

    if (ec == NABTO_DEVICE_EC_OK) {
        return NABTO_EC_OK;
    } else if (ec == NABTO_DEVICE_EC_IAM_DENY) {
        return NABTO_EC_IAM_DENY;
    } else {
        NABTO_LOG_ERROR(LOG, "IAM override function returned invalid error code: (%u) %s", ec, nabto_device_error_get_message(ec));
        return NABTO_EC_IAM_DENY;
    }
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_override_check_access_implementation(NabtoDevice* device, NabtoDeviceIAMCheckAccessCallback cb, void* userData)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (cb != NULL) {
        dev->checkAccessFunctionOverride = cb;
        dev->checkAccessFunctionOverrideUserData = userData;
        dev->core.iam.checkAccessFunction = &nc_iam_check_access_function_override_adapter;
        dev->core.iam.checkAccessFunctionUserData = dev;
    } else {
        dev->core.iam.checkAccessFunction = NULL;
        dev->core.iam.checkAccessFunctionUserData = NULL;
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}
