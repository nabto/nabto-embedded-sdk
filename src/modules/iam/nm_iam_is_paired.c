#include "nm_iam_coap_handler.h"
#include "nm_iam_user.h"
#include "nm_iam.h"
#include "nm_iam_internal.h"

#include <stdlib.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_is_paired_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "pairing", "is-paired", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "Pairing:Get", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    // get user, if user exists, then return 205 else 403.

    struct nm_iam_user* user = nm_iam_find_user_by_coap_request(handler->iam, request);
    if(user) {
        nabto_device_coap_response_set_code(request, 205);
    } else {
        nabto_device_coap_response_set_code(request, 403);
    }
    nabto_device_coap_response_ready(request);
}
