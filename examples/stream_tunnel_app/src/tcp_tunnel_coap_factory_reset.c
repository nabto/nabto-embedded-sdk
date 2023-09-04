#include "tcp_tunnel_coap.h"
#include "tcp_tunnel_ptz_state.h"

#include <cbor.h>
#include <stdlib.h>
#include <modules/iam/nm_iam.h>


static void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request);

//////////////////////////////////////////////////////////////////////////////////////
/// [COAP_ENDPOINT_TEMPLATE]: Endpoint definition
///
/// Add CoAP endpoint definition here and reference it from tunnel_coap_init_handlers()
/// in tcp_tunnel_coap.c. Note the path to the endpoint and the method.
NabtoDeviceError tunnel_factory_reset_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server)
{
    const char* paths[] = { "factory-reset", NULL };
    return tunnel_coap_handler_init(handler, device, tunnel_coap_server, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

//////////////////////////////////////////////////////////////////////////////////////
/// [COAP_ENDPOINT_TEMPLATE]: Implementation
///
/// Add CoAP endpoint implementation here.
void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    // if (!nm_iam_check_access(handler->tunnel_coap_server->iam, nabto_device_coap_request_get_connection_ref(request), "CoAP:FactoryReset", NULL)) {
    //     nabto_device_coap_error_response(request, 403, "Access denied");
    //     return;
    // }
    ptz_state_init(handler->tunnel_coap_server->state);
    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    printf("FACTORY RESET COMPLETE\n");
    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}


