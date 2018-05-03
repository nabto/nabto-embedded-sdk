#include "np_ip_address.h"

bool np_ip_is_v4(struct np_ip_address* ip)
{
    return (ip->type == NABTO_IPV4);
}

bool np_ip_is_v6(struct np_ip_address* ip)
{
    return (ip->type == NABTO_IPV6);
}
