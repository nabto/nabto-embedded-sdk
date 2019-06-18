#ifndef _NC_COAP_PACKET_PRINTER_H_
#define _NC_COAP_PACKET_PRINTER_H_

#include <string.h>
#include <stdint.h>

void nc_coap_packet_print(const char* header, const uint8_t* buffer, size_t bufferSize);

#endif
