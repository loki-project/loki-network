#include "client_contact.hpp"

namespace llarp
{
    static auto logcat = log::Cat("client-intro");

    ClientIntro::ClientIntro(std::string_view buf)
    {
        bt_decode(buf);
    }

    void ClientIntro::bt_encode(oxenc::bt_dict_producer&& subdict) const
    {
        subdict.append("k", pivot_rid.to_view());
        subdict.append("p", pivot_rxid.to_view());
        subdict.append("x", expiry.count());
    }

    bool ClientIntro::bt_decode(std::string_view buf)
    {
        try
        {
            bt_decode(oxenc::bt_dict_consumer{buf});
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "ClientIntro deserialization failed: {}", e.what());
            return false;
        }

        return true;
    }

    void ClientIntro::bt_decode(oxenc::bt_dict_consumer&& btdc)
    {
        pivot_rid.from_string(btdc.require<std::string_view>("k"));
        pivot_rxid.from_string(btdc.require<std::string_view>("p"));
        expiry = std::chrono::milliseconds{btdc.require<int64_t>("x")};
    }

    std::string ClientIntro::to_string() const
    {
        return "[ ClientIntro pivot_rid={}, pivot_hid={}, expiry={} ]"_format(pivot_rid, pivot_rxid, expiry.count());
    }
}  //  namespace llarp
