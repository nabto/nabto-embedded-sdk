#pragma once

#include <vector>
#include <string>

namespace nabto {

class AlpnProtocols {
 public:
    AlpnProtocols(std::vector<std::string> alpns) {
        protocolStrings_ = alpns;
        for (const std::string& alpn : protocolStrings_) {
            protocols_.push_back(alpn.c_str());
        }
        protocols_.push_back(NULL);
    }

    const char** getProtocols() {
        return protocols_.data();
    }
    
 private:
    std::vector<std::string> protocolStrings_;
    std::vector<const char*> protocols_;
};

} // namespace
