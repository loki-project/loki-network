#include "router_contact.hpp"

#include <oxenc/bt_serialize.h>

namespace llarp
{
    static auto logcat = log::Cat("RC");

    void RouterContact::bt_verify(oxenc::bt_dict_consumer& btdc, bool reject_expired) const
    {
        btdc.require_signature("~", [this, reject_expired](ustring_view msg, ustring_view sig) {
            if (sig.size() != 64)
                throw std::runtime_error{"Invalid signature: not 64 bytes"};

            if (reject_expired and is_expired(time_now_ms()))
                throw std::runtime_error{"Rejecting expired RemoteRC!"};

            if (not addr().is_public() and BLOCK_BOGONS)
            {
                auto err = "Unable to verify expired RemoteRC address!";
                log::info(logcat, "{}", err);
                throw std::runtime_error{err};
            }

            if (not crypto::verify(router_id(), msg, sig))
                throw std::runtime_error{"Failed to verify RemoteRC signature"};
        });

        if (not btdc.is_finished())
            throw std::runtime_error{"RemoteRC has some fucked up shit at the end"};

        btdc.finish();
    }

    void RouterContact::bt_load(oxenc::bt_dict_consumer& btdc)
    {
        if (int rc_ver = btdc.require<uint8_t>(""); rc_ver != RC_VERSION)
            throw std::runtime_error{"Invalid RC: do not know how to parse v{} RCs"_format(rc_ver)};

        auto ipv4_port = btdc.require<std::string_view>("4");

        if (ipv4_port.size() != 6)
            throw std::runtime_error{
                "Invalid RC address: expected 6-byte IPv4 IP/port, got {}"_format(ipv4_port.size())};

        sockaddr_in s4;
        s4.sin_family = AF_INET;

        std::memcpy(&s4.sin_addr.s_addr, ipv4_port.data(), 4);
        std::memcpy(&s4.sin_port, ipv4_port.data() + 4, 2);

        _addr = oxen::quic::Address{&s4};

        if (!_addr.is_public())
            throw std::runtime_error{"Invalid RC: IPv4 address is not a publicly routable IP"};

        if (auto ipv6_port = btdc.maybe<std::string_view>("6"))
        {
            if (ipv6_port->size() != 18)
                throw std::runtime_error{
                    "Invalid RC address: expected 18-byte IPv6 IP/port, got {}"_format(ipv6_port->size())};

            sockaddr_in6 s6{};
            s6.sin6_family = AF_INET6;

            std::memcpy(&s6.sin6_addr.s6_addr, ipv6_port->data(), 16);
            std::memcpy(&s6.sin6_port, ipv6_port->data() + 16, 2);

            _addr6.emplace(&s6);
            if (!_addr6->is_public())
                throw std::runtime_error{"Invalid RC: IPv6 address is not a publicly routable IP"};
        }
        else
        {
            _addr6.reset();
        }

        auto netid = btdc.maybe<std::string_view>("i").value_or(llarp::LOKINET_DEFAULT_NETID);

        if (netid != ACTIVE_NETID)
            throw std::runtime_error{
                "Invalid RC netid: expected {}, got {}; this is an RC for a different network!"_format(
                    ACTIVE_NETID, netid)};

        auto pubkey = btdc.require<std::string_view>("p");
        if (pubkey.size() != 32)
            throw std::runtime_error{"Invalid RC pubkey: expected 32 bytes, got {}"_format(pubkey.size())};
        std::memcpy(_router_id.data(), pubkey.data(), 32);

        _timestamp = rc_time{std::chrono::seconds{btdc.require<uint64_t>("t")}};

        auto ver = btdc.require<ustring_view>("v");

        if (ver.size() != 3)
            throw std::runtime_error{"Invalid RC router version: received {} bytes (!= 3)"_format(ver.size())};

        for (int i = 0; i < 3; i++)
            _router_version[i] = ver[i];
    }

    bool RouterContact::write(const fs::path& fname) const
    {
        auto bte = view();

        try
        {
            util::buffer_to_file(fname, bte.data(), bte.size());
        }
        catch (const std::exception& e)
        {
            log::error(logcat, "Failed to write RC to {}: {}", fname, e.what());
            return false;
        }
        return true;
    }

    nlohmann::json RouterContact::extract_status() const
    {
        nlohmann::json obj{
            {"lastUpdated", _timestamp.time_since_epoch().count()},
            {"publicRouter", is_public_addressable()},
            {"identity", _router_id.to_string()},
            {"address", _addr.to_string()}};

        // if (routerVersion)
        // {
        //   obj["routerVersion"] = routerVersion->to_string();
        // }
        // std::vector<nlohmann::json> srv;
        // for (const auto& record : srvRecords)
        // {
        //   srv.emplace_back(record.ExtractStatus());
        // }
        // obj["srvRecords"] = srv;

        return obj;
    }

    bool RouterContact::is_public_addressable() const
    {
        if (_router_version.empty())
            return false;

        return _addr.is_addressable();
    }

    bool RouterContact::is_expired(std::chrono::milliseconds now) const
    {
        return age(now) >= _timestamp.time_since_epoch() + LIFETIME;
    }

    std::chrono::milliseconds RouterContact::time_to_expiry(std::chrono::milliseconds now) const
    {
        const auto expiry = _timestamp.time_since_epoch() + LIFETIME;
        return now < expiry ? expiry - now : 0s;
    }

    std::chrono::milliseconds RouterContact::age(std::chrono::milliseconds now) const
    {
        auto delta = now - _timestamp.time_since_epoch();
        return delta > 0s ? delta : 0s;
    }

    bool RouterContact::expires_within_delta(std::chrono::milliseconds now, std::chrono::milliseconds dlt) const
    {
        return time_to_expiry(now) <= dlt;
    }

    static const std::set<std::string_view> obsolete_bootstraps{
        "7a16ac0b85290bcf69b2f3b52456d7e989ac8913b4afbb980614e249a3723218"sv,
        "e6b3a6fe5e32c379b64212c72232d65b0b88ddf9bbaed4997409d329f8519e0b"sv,
    };

    bool RouterContact::is_obsolete_bootstrap() const
    {
        for (const auto& k : obsolete_bootstraps)
        {
            if (_router_id.ToHex() == k)
                return true;
        }
        return false;
    }

    bool RouterContact::is_obsolete(const RouterContact& rc)
    {
        const auto& hex = rc._router_id.ToHex();

        return obsolete_bootstraps.count(hex);
    }
}  // namespace llarp
