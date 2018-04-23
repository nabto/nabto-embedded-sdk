#include "ip_address.h"

bool nabto_ip_is_v4(struct nabto_ip_address* ip)
{
    return (ip->type == NABTO_IPV4);
}

bool nabto_ip_is_v6(struct nabto_ip_address* ip)
{
    return (ip->type == NABTO_IPV6);
}
