#include "np_mdns_wrapper.h"

void np_mdns_publish_service(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems)
{
    obj->mptr->publish_service(obj, port, instanceName, subtypes, txtItems);
}

void np_mdns_unpublish_service(struct np_mdns* obj)
{
    obj->mptr->unpublish_service(obj);
}
