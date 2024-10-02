#include "contacts.hpp"

#include <llarp/messages/dht.hpp>
#include <llarp/router/router.hpp>

namespace llarp
{
    Contacts::Contacts(Router& r) : _router{r}, _local_key{dht::Key_t::derive_from_rid(r.local_rid())}
    {
        timer_keepalive = std::make_shared<int>(0);
        _introset_nodes = std::make_unique<dht::Bucket<dht::ISNode>>(_local_key, llarp::randint);
    }

    std::optional<service::IntroSetOld> Contacts::get_decrypted_introset(RouterID remote) const
    {
        std::optional<service::IntroSetOld> ret = std::nullopt;

        if (auto encrypted = get_encrypted_introset(dht::Key_t::derive_from_rid(remote));
            auto intro = encrypted->decrypt(remote))
            ret = *intro;

        return ret;
    }

    std::optional<service::EncryptedIntroSet> Contacts::get_encrypted_introset(const dht::Key_t& key) const
    {
        std::optional<service::EncryptedIntroSet> enc = std::nullopt;

        auto& introsets = _introset_nodes->nodes;

        if (auto itr = introsets.find(key); itr != introsets.end() && not itr->second.introset.is_expired())
            enc = itr->second.introset;

        return enc;
    }

    nlohmann::json Contacts::ExtractStatus() const
    {
        nlohmann::json obj{{"services", _introset_nodes->ExtractStatus()}, {"local_key", _local_key.ToHex()}};
        return obj;
    }

    void Contacts::put_intro(service::EncryptedIntroSet enc)
    {
        _introset_nodes->PutNode(std::move(enc));
    }

}  // namespace llarp
