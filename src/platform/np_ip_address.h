#ifndef NP_IP_ADDRESS_H
#define NP_IP_ADDRESS_H

#include <platform/np_types.h>
#include <nn/ip_address.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP address moved to common, this maps names so I do not have fo change the name everywhere
 **/

#define NABTO_IPV4 NN_IPV4
#define NABTO_IPV6 NN_IPV6

#define np_ip_address_type nn_ip_address_type
#define np_ip_address nn_ip_address

#define np_ip_is_v4 nn_ip_is_v4
#define np_ip_is_v6 nn_ip_is_v6

#define np_ip_is_v4_mapped nn_ip_is_v4_mapped
#define np_ip_convert_v4_to_v4_mapped nn_ip_convert_v4_to_v4_mapped
#define np_ip_convert_v4_mapped_to_v4 nn_ip_convert_v4_mapped_to_v4
#define np_ip_address_to_string nn_ip_address_to_string
#define np_ip_address_assign_v4 nn_ip_address_assign_v4
#define np_ip_address_read_v4 nn_ip_address_read_v4

#ifdef __cplusplus
} //extern "C"
#endif

#endif
