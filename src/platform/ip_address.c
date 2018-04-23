#include "ip_address.h"

bool unabto_ip_is_v4(struct unabto_ip_address* ip)
{
    return (ip->type == UNABTO_IPV4);
}

bool unabto_ip_is_v6(struct unabto_ip_address* ip)
{
    return (ip->type == UNABTO_IPV6);
}
