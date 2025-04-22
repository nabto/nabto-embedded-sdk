#ifndef NC_COAP_PACKET_PRINTER_H_
#define NC_COAP_PACKET_PRINTER_H_

#include <string.h>
#include <stdint.h>

#include <platform/np_error_code.h>

np_error_code nc_coap_packet_print(const char* header, const uint8_t* buffer, size_t bufferSize);

#endif
