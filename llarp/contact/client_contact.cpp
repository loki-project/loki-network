#include "client_contact.hpp"

namespace llarp
{
    static auto logcat = log::Cat("client-intro");

    ClientContact::ClientContact(
        Ed25519Hash pk,
        const std::unordered_set<dns::SRVData>& srvs,
        uint16_t proto_flags,
        std::optional<net::ExitPolicy> policy)
        : derived_privatekey{std::move(pk)},
          SRVs{srvs.begin(), srvs.end()},
          protos{proto_flags},
          exit_policy{std::move(policy)}
    {}

    ClientContact::ClientContact(std::string_view buf)
    {
        bt_decode(buf);
    }

    ClientContact ClientContact::generate(
        Ed25519Hash&& pk,
        const std::unordered_set<dns::SRVData>& srvs,
        uint16_t proto_flags,
        std::optional<net::ExitPolicy> policy)
    {
        log::info(logcat, "Generating new ClientContact...");
        return ClientContact{std::move(pk), srvs, proto_flags, std::move(policy)};
    }

    void ClientContact::handle_updated_field(intro_set iset)
    {
        log::trace(logcat, "ClientContact storing updated ClientIntros...");
        if (iset.empty())
            throw std::invalid_argument{"Cannot publish ClientContact with no ClientIntros!"};
        intros = std::move(iset);
    }

    void ClientContact::handle_updated_field(std::unordered_set<dns::SRVData> srvs)
    {
        log::trace(logcat, "ClientContact storing updated SRVs...");
        SRVs = std::move(srvs);
    }

    void ClientContact::handle_updated_field(uint16_t proto)
    {
        log::trace(logcat, "ClientContact storing new protocol types...");
        protos = proto;
    }

    void ClientContact::_regenerate()
    {
        log::debug(logcat, "ClientContact regenerated with updated fields!");
    }

    void ClientContact::bt_encode(std::vector<unsigned char>& buf) const
    {
        bt_encode(oxenc::bt_dict_producer{reinterpret_cast<char*>(buf.data()), buf.size()});
    }

    void ClientContact::bt_encode(oxenc::bt_dict_producer&& btdp) const
    {
        btdp.append("a", pubkey.to_view());

        if (exit_policy)
            exit_policy->bt_encode(btdp.append_dict("e"));

        {
            auto sublist = btdp.append_list("i");

            for (auto& i : intros)
                i.bt_encode(sublist.append_dict());
        }

        btdp.append("p", protos);

        if (not SRVs.empty())
        {
            auto sublist = btdp.append_list("s");
            for (auto& s : SRVs)
                s.bt_encode(sublist.append_dict());
        }
    }

    void ClientContact::bt_decode(std::string_view buf)
    {
        try
        {
            bt_decode(oxenc::bt_dict_consumer{buf});
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "ClientContact deserialization failed: {}", e.what());
            throw;
        }
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

        protos = btdc.require<uint16_t>("p");

        // ditto as above
        if (btdc.skip_until("s"))
        {
            auto sublist = btdc.consume_list_consumer();

            while (not sublist.is_finished())
                SRVs.emplace(sublist.consume_string_view());
        }
    }

    bool ClientContact::is_expired(std::chrono::milliseconds now) const
    {
        // check the last intro to expire
        return intros.rbegin()->is_expired(now);
    }

    EncryptedClientContact ClientContact::encrypt_and_sign()
    {
        EncryptedClientContact enc{};
        
        try
        {
            bt_encode(enc.encrypted);

        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception encrypting and signing client contact: {}", e.what());
        }
        

        return enc;
    }

    EncryptedClientContact EncryptedClientContact::deserialize(std::string_view buf)
    {
        log::info(logcat, "Deserializing EncryptedClientContact...");
        return EncryptedClientContact{buf};
    }

    EncryptedClientContact::EncryptedClientContact(std::string_view buf)
    {
        bt_decode(oxenc::bt_dict_consumer{buf});
    }

    void EncryptedClientContact::bt_encode(oxenc::bt_dict_producer&& btdp) const
    {
        btdp.append("i", blinded_pubkey.to_view());
        btdp.append("n", nonce.to_view());
        btdp.append("t", signed_at.count());
        btdp.append("x", encrypted);
    }

    /** EncryptedClientContact
            "i" blinded local routerID
            "n" nounce
            "t" signing time
            "x" encrypted payload
            "~" signature
    */
    void EncryptedClientContact::bt_decode(oxenc::bt_dict_consumer&& btdc)
    {
        try
        {
            blinded_pubkey.from_string(btdc.require<std::string_view>("i"));
            nonce.from_string(btdc.require<std::string_view>("n"));
            blinded_pubkey.from_string(btdc.require<std::string_view>("i"));
            encrypted = btdc.require<std::vector<unsigned char>>("x");
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "EncryptedClientContact deserialization failed: {}", e.what());
            throw;
        }
    }

    bool EncryptedClientContact::is_expired(std::chrono::milliseconds now) const
    {
        return now >= signed_at + path::DEFAULT_LIFETIME;
    }
}  //  namespace llarp
