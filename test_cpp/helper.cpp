#include "helper.hpp"
std::ostream& operator<<(std::ostream& os, const EC& ec)
{
    os << std::string(nabto_device_error_get_string(ec.ec_));
    return os;
}
