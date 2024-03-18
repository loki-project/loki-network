#pragma once
#include "address.hpp"

#include <llarp/crypto/types.hpp>
#include <llarp/util/str.hpp>

namespace llarp::service
{
    struct EncryptedName
    {
        SymmNonce nonce;
        std::string ciphertext;

        std::optional<Address> Decrypt(std::string_view name) const;
    };

    /// check if an ons name complies with the registration rules
    inline bool is_valid_ons(std::string_view ons_name)
    {
        // make sure it ends with .loki because no fucking shit right?
        if (not ends_with(ons_name, ".loki"))
            return false;

        // strip off .loki suffix
        ons_name = ons_name.substr(0, ons_name.find_last_of('.'));

        // ensure chars are sane
        for (const auto ch : ons_name)
        {
            if (ch == '-')
                continue;
            if (ch == '.')
                continue;
            if (ch >= 'a' and ch <= 'z')
                continue;
            if (ch >= '0' and ch <= '9')
                continue;
            return false;
        }

        // split into domain parts
        const auto parts = split(ons_name, ".");

        // get root domain
        const auto primaryName = parts[parts.size() - 1];
        constexpr size_t MaxNameLen = 32;
        constexpr size_t MaxPunycodeNameLen = 63;

        // check against lns name blacklist
        if (primaryName == "localhost")
            return false;
        if (primaryName == "loki")
            return false;
        if (primaryName == "snode")
            return false;
        // check for dashes
        if (primaryName.find("-") == std::string_view::npos)
            return primaryName.size() <= MaxNameLen;
        // check for dashes and end or beginning
        if (*primaryName.begin() == '-' or *(primaryName.end() - 1) == '-')
            return false;
        // check for punycode name length
        if (primaryName.size() > MaxPunycodeNameLen)
            return false;
        // check for xn--
        return (primaryName[2] == '-' and primaryName[3] == '-') ? (primaryName[0] == 'x' and primaryName[1] == 'n')
                                                                 : true;
    }

}  // namespace llarp::service
