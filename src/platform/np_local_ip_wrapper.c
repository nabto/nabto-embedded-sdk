#include "np_local_ip_wrapper.h"

size_t np_local_ip_get_local_ips(struct np_local_ip* obj,  struct np_ip_address *addrs, size_t addrsSize)
{
    return obj->mptr->get_local_ips(obj, addrs, addrsSize);
}
