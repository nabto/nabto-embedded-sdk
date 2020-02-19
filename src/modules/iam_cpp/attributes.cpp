#include "attributes.hpp"

namespace nabto {
namespace iam {

std::unique_ptr<std::string> Attributes::get(const std::string& key) const
{
    auto it = attributes_.find(key);
    if (it == attributes_.end()) {
        return nullptr;
    }
    return std::make_unique<std::string>(it->second);
}

void Attributes::set(const std::string& key, const std::string& value)
{
    attributes_[key] = value;
}

AttributeMap Attributes::getMap() const
{
    return attributes_;
}

void Attributes::merge(const Attributes& attributes)
{
    for (auto a : attributes.attributes_) {
        attributes_[a.first] = a.second;
    }
}

} } // namespace
