#include "router_id.hpp"

#include <oxenc/base32z.h>

namespace llarp
{
    constexpr std::string_view RELAY_TLD = ".snode";
    constexpr std::string_view CLIENT_TLD = ".loki";

    static auto logcat = log::Cat("routerid");

    std::string RouterID::to_network_address(bool is_relay) const
    {
        std::string b32 = oxenc::to_base32z(begin(), end());
        b32 += is_relay ? RELAY_TLD : CLIENT_TLD;
        return b32;
    }

    std::string RouterID::to_string() const
    {
        std::string b32 = oxenc::to_base32z(begin(), end());
        b32 += RELAY_TLD;
        return b32;
    }

    nlohmann::json RouterID::ExtractStatus() const
    {
        nlohmann::json obj{{"snode", to_string()}, {"hex", ToHex()}};
        return obj;
    }

    void RouterID::from_network_address(std::string_view str)
    {
        if (str.ends_with(RELAY_TLD))
            str.remove_suffix(RELAY_TLD.size());
        else if (str.ends_with(CLIENT_TLD))
            str.remove_suffix(CLIENT_TLD.size());
        else
            throw std::invalid_argument{"RouterID input tld not recognized (input: {})"_format(str)};

        if (str.size() != 52 || !oxenc::is_base32z(str) || !(str.back() == 'o' || str.back() == 'y'))
            throw std::invalid_argument{"RouterID input is incorrect (input: {})"_format(str)};

        oxenc::from_base32z(str.begin(), str.end(), begin());
    }

    bool RouterID::from_relay_address(std::string_view str)
    {
        auto pos = str.find(RELAY_TLD);
        if (pos != str.size() - RELAY_TLD.size())
            return false;
        str.remove_suffix(RELAY_TLD.size());
        // Ensure we have something valid:
        // - must end in a 1-bit value: 'o' or 'y' (i.e. 10000 or 00000)
        // - must have 51 preceeding base32z chars
        // - thus we get 51*5+1 = 256 bits = 32 bytes of output
        if (str.size() != 52 || !oxenc::is_base32z(str) || !(str.back() == 'o' || str.back() == 'y'))
            return false;
        oxenc::from_base32z(str.begin(), str.end(), begin());
        return true;
    }
}  // namespace llarp
