#include "nm_tcptunnel.h"

#include <stdlib.h>

void nm_tcptunnels_init(struct nm_tcptunnels* tunnels)
{
    tunnels->tunnelsSentinel.next = &tunnels->tunnelsSentinel;
    tunnels->tunnelsSentinel.prev = &tunnels->tunnelsSentinel;
    // TODO make it customizable.
    tunnels->defaultPort = 22;
    tunnels->defaultHost.type = NABTO_IPV4;
    tunnels->defaultHost.v4.addr[0] = 0x7f;
    tunnels->defaultHost.v4.addr[1] = 0x00;
    tunnels->defaultHost.v4.addr[2] = 0x00;
    tunnels->defaultHost.v4.addr[3] = 0x01;


}

void nm_tcptunnels_deinit()
{

}

struct nm_tcptunnel* nm_tcptunnel_create(struct nm_tcptunnels* tunnels)
{
    struct nm_tcptunnel* tunnel = calloc(1, sizeof(struct nm_tcptunnel));

    tunnel->tunnels = tunnels;
    tunnel->id = tunnels->idCounter;
    tunnels->idCounter++;

    // insert into list of tunnels
    struct nm_tcptunnel* before = tunnels->tunnelsSentinel.prev;
    struct nm_tcptunnel* after = &tunnels->tunnelsSentinel;

    before->next = tunnel;
    tunnel->next = after;
    after->prev = tunnel;
    tunnel->prev = before;

    return tunnel;
}
