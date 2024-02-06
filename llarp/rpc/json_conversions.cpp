#include "json_conversions.hpp"

#include <nlohmann/json.hpp>

namespace llarp
{
    void to_json(nlohmann::json& j, const IP_range_deprecated& ipr)
    {
        j = ipr.to_string();
    }

    void from_json(const nlohmann::json& j, IP_range_deprecated& ipr)
    {
        ipr = IP_range_deprecated{j.get<std::string>()};
    }

}  // namespace llarp
