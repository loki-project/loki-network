#include <llarp/bootstrap.hpp>

#include <initializer_list>

namespace llarp
{
    std::unordered_map<std::string, BootstrapList> load_bootstrap_fallbacks()
    {
        std::unordered_map<std::string, BootstrapList> fallbacks;

        for (const auto& [network, bootstrap] : std::initializer_list<std::pair<std::string, std::string_view>>{
                 //
             })
        {
            if (network != RouterContact::ACTIVE_NETID)
                continue;

            auto& bsl = fallbacks[network];
            bsl.bt_decode(bootstrap);
        }

        return fallbacks;
    }
}  // namespace llarp
