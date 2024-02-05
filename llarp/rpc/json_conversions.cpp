#include "json_conversions.hpp"

#include <nlohmann/json.hpp>

namespace llarp
{
    void to_json(nlohmann::json& j, const IPRange& ipr)
    {
        j = ipr.to_string();
    }

    void from_json(const nlohmann::json& j, IPRange& ipr)
    {
        ipr = IPRange{j.get<std::string>()};
    }

}  // namespace llarp
