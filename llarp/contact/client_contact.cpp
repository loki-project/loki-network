#include "client_contact.hpp"

#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    static auto logcat = log::Cat("client-intro");

    ClientContact::ClientContact(
        Ed25519PrivateData private_data,
        PubKey pk,
        const std::unordered_set<dns::SRVData>& srvs,
        uint16_t proto_flags,
        std::optional<net::ExitPolicy> policy)
        : derived_privatekey{std::move(private_data)},
          pubkey{std::move(pk)},
          SRVs{srvs.begin(), srvs.end()},
          protos{proto_flags},
          exit_policy{std::move(policy)}
    {}

    ClientContact::ClientContact(std::string&& buf)
    {
        bt_decode(oxenc::bt_dict_consumer{buf});
    }

    ClientContact ClientContact::generate(
        Ed25519PrivateData&& private_data,
        PubKey&& pk,
        const std::unordered_set<dns::SRVData>& srvs,
        uint16_t proto_flags,
        std::optional<net::ExitPolicy> policy)
    {
        log::info(logcat, "Generating new ClientContact...");
        return ClientContact{std::move(private_data), std::move(pk), srvs, proto_flags, std::move(policy)};
    }

    void ClientContact::handle_updated_field(intro_set iset)
    {
        if (iset.empty())
            throw std::invalid_argument{"Cannot publish ClientContact with no ClientIntros!"};
        intros = std::move(iset);
        log::debug(logcat, "ClientContact stored updated ClientIntros (n={})...", intros.size());
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
        buf.resize(bt_encode(oxenc::bt_dict_producer{reinterpret_cast<char*>(buf.data()), buf.size()}));
    }

    size_t ClientContact::bt_encode(oxenc::bt_dict_producer&& btdp) const
    {
        btdp.append<uint8_t>("", ClientContact::CC_VERSION);

        btdp.append("a", pubkey.to_view());

        if (exit_policy)
            exit_policy->bt_encode(btdp.append_dict("e"));

        {
            auto sublist = btdp.append_list("i");

            for (auto& i : intros)
                i.bt_encode(sublist.append_dict());
        }

        btdp.append<uint16_t>("p", protos);

        if (not SRVs.empty())
        {
            auto sublist = btdp.append_list("s");
            for (auto& s : SRVs)
                s.bt_encode(sublist.append_dict());
        }

        return btdp.view().size();
    }

    void ClientContact::bt_decode(oxenc::bt_dict_consumer&& btdc)
    {
        auto version = btdc.require<uint8_t>("");

        if (ClientContact::CC_VERSION != version)
            throw std::runtime_error{
                "Deserialized ClientContact with incorrect version! (Received:{}, expected:{})"_format(
                    version, ClientContact::CC_VERSION)};

        pubkey.from_string(btdc.require<std::string_view>("a"));

        if (btdc.skip_until("e"))
        {
            exit_policy->bt_decode(btdc.consume_dict_consumer());
        }

        btdc.required("i");

        {
            auto sublist = btdc.consume_list_consumer();

            while (not sublist.is_finished())
                intros.emplace(sublist.consume_dict_consumer());
        }

        protos = btdc.require<uint16_t>("p");

        if (btdc.skip_until("s"))
        {
            auto sublist = btdc.consume_list_consumer();

            while (not sublist.is_finished())
                SRVs.emplace(sublist.consume_dict_consumer());
        }
    }

    bool ClientContact::is_expired(std::chrono::milliseconds now) const
    {
        // check the last intro to expire
        return intros.rbegin()->is_expired(now);
    }

    EncryptedClientContact ClientContact::encrypt_and_sign() const
    {
        EncryptedClientContact enc{};

        try
        {
            enc.blinded_pubkey = derived_privatekey.to_pubkey();
            bt_encode(enc.encrypted);

            if (not crypto::xchacha20(enc.encrypted.data(), enc.encrypted.size(), pubkey.data(), enc.nonce.data()))
                throw std::runtime_error{"Failed to encrypt ClientContact bt-payload!"};

            enc.signed_at = llarp::time_now_ms();

            oxenc::bt_dict_producer btdp;
            enc.bt_encode(btdp);

            btdp.append_signature("~", [&](ustring_view to_sign) {
                if (not crypto::sign(enc.sig, derived_privatekey, to_sign.data(), to_sign.size()))
                    throw std::runtime_error{"Failed to sign EncryptedClientContact payload!"};
                return enc.sig.to_view();
            });

            enc._bt_payload = std::move(btdp).str();
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception encrypting and signing client contact: {}", e.what());
            throw;
        }

        return enc;
    }

    std::string ClientContact::to_string() const
    {
        return "CC:['a'={} | 'e'={} | 'i'={{{}}} | 'p'={} | 's'={}]"_format(
            pubkey, exit_policy.has_value(), fmt::join(intros, ","), protos, not SRVs.empty());
    }

    EncryptedClientContact EncryptedClientContact::deserialize(std::string_view buf)
    {
        log::info(logcat, "Deserializing EncryptedClientContact...");
        return EncryptedClientContact{buf};
    }

    EncryptedClientContact::EncryptedClientContact(std::string_view buf) : _bt_payload{buf}
    {
        bt_decode(oxenc::bt_dict_consumer{_bt_payload});
    }

    void EncryptedClientContact::bt_encode(oxenc::bt_dict_producer& btdp) const
    {
        btdp.append("i", blinded_pubkey.to_view());
        btdp.append("n", nonce.to_view());
        btdp.append("t", signed_at.count());
        btdp.append("x", std::string_view{reinterpret_cast<const char*>(encrypted.data()), encrypted.size()});
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
            signed_at = std::chrono::milliseconds{btdc.require<uint64_t>("t")};

            // TESTNET: TOFIX: change this after oxenc span PR is merged
            auto enc = btdc.require<std::string_view>("x");
            encrypted.resize(enc.size());
            std::memcpy(encrypted.data(), enc.data(), enc.size());

            sig.from_string(btdc.require<std::string_view>("~"));
        }
        catch (const std::exception& e)
        {
            log::critical(
                logcat,
                "EncryptedClientContact deserialization failed: {} : payload: {}",
                e.what(),
                buffer_printer{_bt_payload});
            throw;
        }
    }

    std::optional<ClientContact> EncryptedClientContact::decrypt(const PubKey& root)
    {
        std::optional<ClientContact> cc = std::nullopt;
        std::string payload{reinterpret_cast<char*>(encrypted.data()), encrypted.size()};

        if (crypto::xchacha20(
                reinterpret_cast<unsigned char*>(payload.data()), payload.size(), root.data(), nonce.data()))
        {
            log::debug(logcat, "EncryptedClientContact decrypted successfully...");
            cc = ClientContact{std::move(payload)};
        }
        else
            log::warning(logcat, "Failed to decrypt EncryptedClientContact!");

        return cc;
    }

    bool EncryptedClientContact::verify() const
    {
        try
        {
            oxenc::bt_dict_consumer btdc{_bt_payload};

            btdc.require_signature("~", [this](ustring_view m, ustring_view s) {
                if (s.size() != 64)
                    throw std::runtime_error{"Invalid signature: not 64 bytes"};

                if (not crypto::verify(blinded_pubkey, m, s))
                    throw std::runtime_error{"Failed to verify EncryptedClientContact signature!"};
            });
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return false;
        }

        log::info(logcat, "Successfully verified EncryptedClientContact!");

        return true;
    }

    bool EncryptedClientContact::is_expired(std::chrono::milliseconds now) const
    {
        return now >= signed_at + path::DEFAULT_LIFETIME;
    }
}  //  namespace llarp
