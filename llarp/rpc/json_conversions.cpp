#include "json_conversions.hpp"

#include <nlohmann/json.hpp>

namespace llarp
{
    static auto logcat = log::Cat("RPC-conversions");

    void to_json(nlohmann::json& j, const IPRange& ipr) { j = ipr.to_string(); }

    void from_json(const nlohmann::json& j, IPRange& ipr)
    {
        if (auto maybe = IPRange::from_string(j.get<std::string>()))
            ipr = *maybe;
        else
            log::critical(logcat, "Failed to parse IPRange from json!");
    }

}  // namespace llarp
