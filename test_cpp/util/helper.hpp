#pragma once

#include <nabto/nabto_device.h>
#include <sstream>

// error code print helper
class EC {
 public:
    EC(const NabtoDeviceError ec)
        : ec_(ec)
    {
    }
    bool operator==(EC right) const {
        return right.ec_ == ec_;
    }
 private:
    NabtoDeviceError ec_;
    friend std::ostream& operator<<(std::ostream& os, const EC& dt);
};
