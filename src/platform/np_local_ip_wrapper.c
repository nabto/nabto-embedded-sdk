#include "np_local_ip_wrapper.h"

size_t np_local_ip_get_local_ips(struct np_local_ip* obj,  struct np_ip_address *addrs, size_t addrsSize)
{
    return obj->vptr->get_local_ips(obj->data, addrs, addrsSize);
}
