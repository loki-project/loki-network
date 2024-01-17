#include "address.hpp"

#include <llarp/crypto/crypto.hpp>

#include <oxenc/base32z.h>

#include <algorithm>

namespace llarp::service
{
    const std::set<std::string> Address::AllowedTLDs = {".loki", ".snode"};

    bool Address::PermitTLD(const char* tld)
    {
        std::string gtld(tld);
        std::transform(gtld.begin(), gtld.end(), gtld.begin(), ::tolower);
        return AllowedTLDs.count(gtld) != 0;
    }

    std::string Address::ToString(const char* tld) const
    {
        if (!PermitTLD(tld))
            return "";
        std::string str;
        if (subdomain.size())
        {
            str = subdomain;
            str += '.';
        }
        str += oxenc::to_base32z(begin(), end());
        str += tld;
        return str;
    }

    bool Address::FromString(std::string_view str, const char* tld)
    {
        if (!PermitTLD(tld))
            return false;
        // Find, validate, and remove the .tld
        const auto pos = str.find_last_of('.');
        if (pos == std::string::npos)
            return false;
        if (str.substr(pos) != tld)
            return false;
        str = str.substr(0, pos);

        // copy subdomains if they are there (and strip them off)
        const auto idx = str.find_last_of('.');
        if (idx != std::string::npos)
        {
            subdomain = str.substr(0, idx);
            str.remove_prefix(idx + 1);
        }

        // Ensure we have something valid:
        // - must end in a 1-bit value: 'o' or 'y' (i.e. 10000 or 00000)
        // - must have 51 preceeding base32z chars
        // - thus we get 51*5+1 = 256 bits = 32 bytes of output
        if (str.size() != 52 || !oxenc::is_base32z(str) || !(str.back() == 'o' || str.back() == 'y'))
            return false;

        oxenc::from_base32z(str.begin(), str.end(), begin());
        return true;
    }

    dht::Key_t Address::ToKey() const
    {
        PubKey k;
        crypto::derive_subkey(k, PubKey(data()), 1);
        return dht::Key_t{k.as_array()};
    }

}  // namespace llarp::service
