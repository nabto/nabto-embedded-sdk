#pragma once

#include <map>
#include <string>
#include <memory>

namespace nabto {
namespace iam {

typedef std::map<std::string, std::string> AttributeMap;

class Attributes {
 public:
    Attributes() {}
    Attributes(AttributeMap map) : attributes_(map) {}
    std::unique_ptr<std::string> get(const std::string& key) const;
    AttributeMap getMap() const;
    void merge(const Attributes& attributes);
    bool empty() const
    {
        return attributes_.empty();
    }
 private:
    AttributeMap attributes_;
};

} } // namespace
