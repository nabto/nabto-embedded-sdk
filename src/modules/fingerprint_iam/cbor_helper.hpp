#pragma once

namespace nabto {
namespace fingerprint_iam {

class CborHelper {
 public:
    static bool initCborParser(NabtoDeviceCoapRequest* request, CborParser& parser, CborValue& cborValue, std::string& errorDescription)
    {
        uint16_t contentFormat;
        NabtoDeviceError ec;
        ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
        if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            errorDescription = "Invalid Content Format";
            return false;
        }
        void* payload;
        size_t payloadSize;
        if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
            errorDescription = "Missing payload";
            return false;
        }
        cbor_parser_init((const uint8_t*)payload, payloadSize, 0, &parser, &cborValue);
        return true;
    }

    static bool decodeKvString(CborValue& map, const std::string& key, std::string& value)
    {
        if (!cbor_value_is_map(&map)) {
            return false;
        }
        CborValue nameValue;
        cbor_value_map_find_value(&map, key.c_str(), &nameValue);
        return decodeString(nameValue, value);
    }

    static bool decodeString(CborValue& nameValue, std::string& value)
    {
        if (cbor_value_is_text_string(&nameValue)) {
            size_t nameLength;
            cbor_value_calculate_string_length (&nameValue, &nameLength);
            if (nameLength < 1024) {
                std::vector<char> buf(nameLength);
                size_t copySize = buf.size();
                if (cbor_value_copy_text_string (&nameValue, buf.data(), &copySize, NULL) == CborNoError) {
                    value = std::string(buf.data(), nameLength);
                    return true;
                }
            }
        }
        return false;
    }
};


} } // namespace
