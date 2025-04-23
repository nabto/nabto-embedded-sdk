#include "nc_coap_packet_printer.h"
#include <nabto_coap/nabto_coap.h>
#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <stdarg.h>
#include <stdio.h>

#define LOG NABTO_LOG_MODULE_COAP

static const char* blockToString(uint32_t value)
{
    uint32_t blockSize = 16 << (value & 0x7);
    uint32_t more = (value & 0xF) >> 3;
    uint32_t num = value >> 4;


    //strlen("4294967296/256/65536") + 1 == 21;
    static char buffer[21];
    memset(buffer, 0, 21);

    sprintf(buffer, "%" PRIu32 "/%" PRIu8 "/%" PRIu16, num, (uint8_t)more, (uint16_t)blockSize);
    return buffer;
}

static const char* tokenToString(nabto_coap_token token)
{
    // tokens is opto 8 bytes long, 16 chars in hex
    static char buffer[17];
    memset(buffer, 0, 17);
    char* ptr = buffer;
    for (size_t i = 0; i < token.tokenLength; i++) {
        int wrote = sprintf(ptr, "%02hhx", token.token[i]);
        ptr += wrote;
    }
    return buffer;
}

static const char* coapTypeToString(nabto_coap_type type) {
    switch (type) {
        case NABTO_COAP_TYPE_CON: return "CON";
        case NABTO_COAP_TYPE_NON: return "NON";
        case NABTO_COAP_TYPE_ACK: return "ACK";
        case NABTO_COAP_TYPE_RST: return "RST";
    }
    // never here, only 4 types exist
    return "UNKNOWN";
}

static const char* coapCodeToString(nabto_coap_code code)
{
    uint8_t realCode = (uint8_t)code;
    uint8_t codeClass = realCode >> 5;
    static char buffer[15];
    memset(buffer, 0, 15);

    if (codeClass == 0) {
        switch (realCode & 0x1f) {
            case NABTO_COAP_CODE_EMPTY: return "EMPTY";
            case NABTO_COAP_CODE_GET: return "GET";
            case NABTO_COAP_CODE_POST: return "POST";
            case NABTO_COAP_CODE_PUT: return "PUT";
            case NABTO_COAP_CODE_DELETE: return "DELETE";
            default: break;// handled below
        }
    }
    if (codeClass > 1 && codeClass <= 5) {
        sprintf(buffer, "%" PRIu8 "%02" PRIu8, codeClass, (uint8_t)(realCode & 0x1f));
        return buffer;
    }
    sprintf(buffer, "UNKNOWN(%" PRIu8 ")", realCode);
    return buffer;
}

const char* coapOptionToString(uint16_t option)
{
    static char buffer[15];
    memset(buffer, 0, 15);

    switch(option) {
        case NABTO_COAP_OPTION_IF_MATCH: return "IF_MATCH";
        case NABTO_COAP_OPTION_URI_HOST: return "URI_HOST";
        case NABTO_COAP_OPTION_ETAG: return "ETAG";
        case NABTO_COAP_OPTION_IF_NONE_MATCH: return "IF_NONE_MATCH";
        case NABTO_COAP_OPTION_URI_PORT: return "URI_PORT";
        case NABTO_COAP_OPTION_LOCATION_PATH: return "LOCATION_PATH";
        case NABTO_COAP_OPTION_URI_PATH: return "URI_PATH";
        case NABTO_COAP_OPTION_CONTENT_FORMAT: return "CONTENT_FORMAT";
        case NABTO_COAP_OPTION_MAX_AGE: return "MAX_AGE";
        case NABTO_COAP_OPTION_URI_QUERY: return "URI_QUERY";
        case NABTO_COAP_OPTION_ACCEPT: return "ACCEPT";
        case NABTO_COAP_OPTION_LOCATION_QUERY: return "LOCATION_QUERY";
        case NABTO_COAP_OPTION_SIZE2: return "SIZE2";
        case NABTO_COAP_OPTION_PROXY_URI: return "PROXY_URI";
        case NABTO_COAP_OPTION_PROXY_SCHEME: return "PROXY_SCHEME";
        case NABTO_COAP_OPTION_SIZE1: return "OPTION_SIZE1";
        default: break;// handled below
    }
    sprintf(buffer, "UNKNOWN(%" PRIu16 ")", option);
    return buffer;
}

static char* safeWrite(char* buffer, char* end, const char* format, ...)
{
    va_list args;
    int written = 0;
    if (buffer == NULL) {
        return NULL;
    }
    if (end < buffer) {
        return NULL;
    }
    size_t maxLength = (end - buffer);
    va_start(args, format);
    written = vsnprintf(buffer, maxLength, format, args);
    va_end(args);
    if (written < 0) {
        return NULL;
    }
    return buffer + written;
}

np_error_code nc_coap_packet_print(const char* header, const uint8_t* packet, size_t packetSize)
{
    size_t bufferLength = 1024;
    char* buffer = np_calloc(bufferLength, 1);
    if (buffer == NULL)
    {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    char* ptr = buffer;
    // Ensure room for a null terminator.
    char* end = buffer+(bufferLength-1);
    ptr = safeWrite(ptr, end, "%s", header);
    struct nabto_coap_incoming_message message;
    if (!nabto_coap_parse_message(packet, packetSize, &message)) {
        ptr = safeWrite(ptr, end, "Invalid packet");
    } else {
        ptr = safeWrite(ptr, end, "Type: %s, Code: %s, MessageId: %d, Token: %s",
                        coapTypeToString(message.type), coapCodeToString(message.code),
                        message.messageId, tokenToString(message.token));
        struct nabto_coap_option_iterator iteratorData;
        struct nabto_coap_option_iterator* iterator = &iteratorData;
        nabto_coap_option_iterator_init(iterator, message.options, message.options + message.optionsLength);
        iterator = nabto_coap_get_next_option(iterator);
        ptr = safeWrite(ptr, end, ", Options:");
        while (iterator != NULL) {
            size_t optionDataLength = iterator->optionDataEnd - iterator->optionDataBegin;
            uint32_t value = 0;
            if (iterator->option == NABTO_COAP_OPTION_URI_PATH) {
                ptr = safeWrite(ptr, end, ", Uri-Path: %.*s", optionDataLength, iterator->optionDataBegin);
            } else if (iterator->option == NABTO_COAP_OPTION_URI_HOST) {
                ptr = safeWrite(ptr, end, ", Uri-Host: %.*s", optionDataLength, iterator->optionDataBegin);
            } else if (iterator->option == NABTO_COAP_OPTION_URI_PORT &&
                       nabto_coap_parse_variable_int(iterator->optionDataBegin, iterator->optionDataEnd, 3, &value))
            {
                ptr = safeWrite(ptr, end, ", Uri-Port: %" PRIu32 , value);
            } else if (iterator->option == NABTO_COAP_OPTION_BLOCK1 &&
                       nabto_coap_parse_variable_int(iterator->optionDataBegin, iterator->optionDataEnd, 3, &value))
            {
                ptr = safeWrite(ptr, end, ", Block1: %s", blockToString(value));
            } else if (iterator->option == NABTO_COAP_OPTION_BLOCK2 &&
                       nabto_coap_parse_variable_int(iterator->optionDataBegin, iterator->optionDataEnd, 3, &value))
            {
                ptr = safeWrite(ptr, end, ", Block2: %s", blockToString(value));
            } else {
                ptr = safeWrite(ptr, end, ", %s: OptionDataLength: %u", coapOptionToString(iterator->option), (unsigned int)optionDataLength);
            }
            iterator = nabto_coap_get_next_option(iterator);

        }
        ptr = safeWrite(ptr, end, ", Payload Length: %d", message.payloadLength);

    }
    if (ptr != NULL) {
        NABTO_LOG_TRACE(LOG, "%s", buffer);
    } else {
        NABTO_LOG_TRACE(LOG, "Can not print coap packet");
    }
    np_free(buffer);
    return NABTO_EC_OK;
}
