#pragma once

#include <modules/fingerprint_iam/fingerprint_iam.hpp>

bool init_default_policies(const std::string& defaultPolicies);
bool load_policies(const std::string& policiesFile, nabto::fingerprint_iam::FingerprintIAM& iam);


class TcpTunnelService {
 public:
    std::string id_;
    std::string type_;
    std::string host_;
    uint16_t port_;
};

bool init_default_services(const std::string& servicesFile);
bool load_services(const std::string& servicesFile, std::vector<TcpTunnelService>& services);
