#ifndef NP_MDNS_WRAPPER_H_
#define NP_MDNS_WRAPPER_H_

#include "interfaces/np_mdns.h"

void np_mdns_publish_service(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems);
void np_mdns_unpublish_service(struct np_mdns* obj);


#endif
