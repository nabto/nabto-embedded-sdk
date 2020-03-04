#pragma once

#include <modules/fingerprint_iam/fingerprint_iam.hpp>

bool init_default_policies(const std::string& defaultPolicies);
bool load_policies(const std::string& policiesFile, nabto::fingerprint_iam::FingerprintIAM& iam);


bool init_default_services(const std::string& servicesFile);
bool load_services(const std::string& servicesFile, NabtoDevice* device);
