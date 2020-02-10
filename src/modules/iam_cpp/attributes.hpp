#pragma once

#include "attribute.hpp"
#include <map>
#include <string>
#include <memory>

namespace nabto {
namespace iam {

typedef std::map<std::string, Attribute> AttributeMap;

class Attributes {
 public:
    Attributes() {}
    Attributes(AttributeMap map) : attributes_(map) {}
    std::unique_ptr<Attribute> get(const std::string& key) const;
    AttributeMap getMap() const;
    void merge(const Attributes& attributes);
 private:
    AttributeMap attributes_;
};

} } // namespace
