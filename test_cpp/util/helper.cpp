#include "helper.hpp"
std::ostream& operator<<(std::ostream& os, const EC& ec)
{
    os << std::string(nabto_device_error_get_string(ec.ec_));
    return os;
}

namespace nabto {
namespace test {

size_t fromHex(const std::string str, uint8_t* data)
{
    size_t dataLength = str.length() / 2;
    size_t i;
    unsigned int value;
    for (i = 0; i < dataLength && sscanf(str.data() + i * 2, "%2x", &value) == 1; i++) {
        data[i] = (uint8_t)value;
    }
    return dataLength;
}

}
}
