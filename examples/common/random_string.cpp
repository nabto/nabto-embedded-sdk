#include "random_string.hpp"

#include <random>
#include <string>

namespace nabto {
namespace examples {
namespace common {

std::string random_string(size_t n)
{
    const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);

    std::string randomString;

    for (std::size_t i = 0; i < n; ++i)
    {
        randomString += characters[distribution(generator)];
    }

    return randomString;
}

} } } // namespace
