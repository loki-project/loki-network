#include "client_contact.hpp"

namespace llarp
{
    static auto logcat = log::Cat("client-intro");

    ClientContact::ClientContact(std::string_view buf)
    {
        bt_decode(buf);
    }

    std::string ClientContact::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        btdp.append("a", pubkey.to_view());

        if (exit_policy)
            exit_policy->bt_encode(btdp.append_dict("e"));

        {
            auto sublist = btdp.append_list("i");

            for (auto& i : intros)
                i.bt_encode(sublist.append_dict());
        }

        if (not supported_protos.empty())
        {
            auto sublist = btdp.append_list("p");
            for (auto& p : supported_protos)
                sublist.append(static_cast<uint64_t>(p));
        }

        if (not SRVs.empty())
        {
            auto sublist = btdp.append_list("s");
            for (auto& s : SRVs)
                s.bt_encode(sublist.append_dict());
        }

        return std::move(btdp).str();
    }

    bool ClientContact::bt_decode(std::string_view buf)
    {
        try
        {
            bt_decode(oxenc::bt_dict_consumer{buf});
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "ClientContact deserialization failed: {}", e.what());
            return false;
        }

        return true;
    }

    void ClientContact::bt_decode(oxenc::bt_dict_consumer&& btdc)
    {
        pubkey.from_string(btdc.require<std::string_view>("a"));

        if (auto maybe_subdict = btdc.maybe<std::string_view>("e"))
        {
            exit_policy->bt_decode(oxenc::bt_dict_consumer{*maybe_subdict});
        }

        btdc.required("i");

        {
            auto sublist = btdc.consume_list_consumer();

            while (not sublist.is_finished())
                intros.emplace(sublist.consume_string_view());
        }

        // check, since we only add "p" if supported_protos is not empty (TESTNET: DISCUSS: an ALL type makes sense?)
        if (btdc.skip_until("p"))
        {
            auto sublist = btdc.consume_list_consumer();

            while (not sublist.is_finished())
                supported_protos.push_back(service::ProtocolType{sublist.consume_integer<uint64_t>()});
        }

        // ditto as above
        if (btdc.skip_until("s"))
        {
            auto sublist = btdc.consume_list_consumer();

            while (not sublist.is_finished())
                SRVs.emplace_back(sublist.consume_string_view());
        }
    }

    bool ClientContact::is_expired(std::chrono::milliseconds now) const
    {
        // check the last intro to expire
        return intros.rbegin()->is_expired(now);
    }
}  //  namespace llarp
