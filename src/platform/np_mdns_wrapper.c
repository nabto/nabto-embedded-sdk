#include "np_mdns_wrapper.h"

void np_mdns_publish_service(struct np_mdns* obj, uint16_t port, const char* productId, const char* deviceId)
{
    obj->vptr->publish_service(obj, port, productId, deviceId);
}
