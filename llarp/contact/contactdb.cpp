#include "contactdb.hpp"

#include <llarp/router/router.hpp>

namespace llarp
{
    ContactDB::ContactDB(Router& r) : _router{r}, _local_key{dht::Key_t::derive_from_rid(r.local_rid())}
    {
        timer_keepalive = std::make_shared<int>(0);
        _introset_nodes = std::make_unique<dht::Bucket<dht::ISNode>>(_local_key, llarp::randint);
    }

    // std::optional<ClientContact> ContactDB::get_decrypted_cc(RouterID remote) const
    // {
    //     std::optional<ClientContact> ret = std::nullopt;

    //     (void)remote;
    //     // TESTNET: TODO: finish this after implementing CC encrypt/decrypt

    //     return ret;
    // }

    // std::optional<EncryptedClientContact> ContactDB::get_encrypted_cc(const dht::Key_t& key) const
    // {
    //     std::optional<EncryptedClientContact> enc = std::nullopt;

    //     auto& clientcontacts = _cc_nodes->nodes;

    //     if (auto itr = clientcontacts.find(key);
    //         itr != clientcontacts.end() && not itr->second.client_contact.is_expired())
    //         enc = itr->second.client_contact;

    //     return enc;
    // }

    std::optional<service::IntroSetOld> ContactDB::get_decrypted_introset(RouterID remote) const
    {
        std::optional<service::IntroSetOld> ret = std::nullopt;

        if (auto encrypted = get_encrypted_introset(dht::Key_t::derive_from_rid(remote));
            auto intro = encrypted->decrypt(remote))
            ret = *intro;

        return ret;
    }

    std::optional<service::EncryptedIntroSet> ContactDB::get_encrypted_introset(const dht::Key_t& key) const
    {
        std::optional<service::EncryptedIntroSet> enc = std::nullopt;

        auto& introsets = _introset_nodes->nodes;

        if (auto itr = introsets.find(key); itr != introsets.end() && not itr->second.introset.is_expired())
            enc = itr->second.introset;

        return enc;
    }

    nlohmann::json ContactDB::ExtractStatus() const
    {
        nlohmann::json obj{{"services", _introset_nodes->ExtractStatus()}, {"local_key", _local_key.ToHex()}};
        return obj;
    }

    void ContactDB::put_intro(service::EncryptedIntroSet enc)
    {
        _introset_nodes->put_node(std::move(enc));
    }

}  //  namespace llarp
