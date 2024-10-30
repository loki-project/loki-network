#pragma once

#include <llarp/crypto/types.hpp>
#include <llarp/path/path_types.hpp>

#include <oxenc/bt.h>

#include <iostream>
#include <set>

namespace llarp
{
    struct ClientIntro
    {
        RouterID pivot_rid;
        HopID pivot_rxid;  // RXID at the pivot
        std::chrono::milliseconds expiry{0s};
        uint64_t version{llarp::constants::proto_version};

        ClientIntro() = default;
        ClientIntro(std::string_view buf);

        bool is_expired(std::chrono::milliseconds now = llarp::time_now_ms()) const { return now >= expiry; }

        void bt_encode(oxenc::bt_dict_producer&& subdict) const;

        // Does not throw, returns true/false
        bool bt_decode(std::string_view buf);

      protected:
        // Throws if unsuccessful, must take BTDC in invocation
        void bt_decode(oxenc::bt_dict_consumer&& btdc);

      public:
        auto operator<=>(const ClientIntro& other) const
        {
            return std::tie(pivot_rid, pivot_rxid, expiry, version)
                <=> std::tie(other.pivot_rid, other.pivot_rxid, other.expiry, other.version);
        }

        bool operator==(const ClientIntro& other) const { return (*this <=> other) == 0; }

        bool operator<(const ClientIntro& other) const
        {
            return std::tie(pivot_rid, pivot_rxid, expiry, version)
                < std::tie(other.pivot_rid, other.pivot_rxid, other.expiry, other.version);
        }

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

    struct ClientIntroComp
    {
        bool operator()(const ClientIntro& lhs, const ClientIntro& rhs) const { return lhs.expiry < rhs.expiry; }
    };

    using intro_queue = std::priority_queue<ClientIntro, std::vector<ClientIntro>, ClientIntroComp>;
    using intro_set = std::set<ClientIntro, ClientIntroComp>;

}  //  namespace llarp

namespace std
{
    template <>
    struct hash<llarp::ClientIntro>
    {
        size_t operator()(const llarp::ClientIntro& i) const
        {
            return std::hash<llarp::PubKey>{}(i.pivot_rid) ^ std::hash<llarp::HopID>{}(i.pivot_rxid);
        }
    };
}  //  namespace std
