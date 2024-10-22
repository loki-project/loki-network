#pragma once

#include <llarp/crypto/types.hpp>
#include <llarp/util/str.hpp>

#include <oxenc/bt.h>

namespace llarp
{
    struct NetworkAddress;

    /** Holds an entire ONS Record returned from a succfessful request to the `lookup_name` endpoint.
        When transmitted over the wire back to the calling instance, it is bt-encoded and the ONS hash
        ('ciphertext') is decrypted using the ons_name.

        bt-encoded keys:
            'c' : ciphertext
            'n' : nonce
    */
    struct EncryptedSNSRecord
    {
      private:
        explicit EncryptedSNSRecord(std::string bt);
        bool bt_decode(oxenc::bt_dict_consumer& btdc);

      public:
        SymmNonce nonce;
        std::string ciphertext;

        EncryptedSNSRecord() = default;

        static std::optional<EncryptedSNSRecord> construct(std::string bt);

        std::string bt_encode() const;

        bool bt_decode(std::string bt);

        std::optional<NetworkAddress> decrypt(std::string_view ons_name) const;
    };

    /// check if an ons name complies with the registration rules
    inline bool is_valid_ons(std::string_view ons_name)
    {
        // make sure it ends with .loki because no fucking shit right?
        if (not ons_name.ends_with(".loki"))
            return false;

        // strip off .loki suffix
        ons_name.remove_suffix(5);

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
}  // namespace llarp
