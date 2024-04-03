#include "contacts.hpp"

#include <llarp/messages/dht.hpp>
#include <llarp/router/router.hpp>

namespace llarp
{
    Contacts::Contacts(Router& r) : _router{r}, _local_key{dht::Key_t::derive_from_rid(r.pubkey())}
    {
        timer_keepalive = std::make_shared<int>(0);
        _introset_nodes = std::make_unique<dht::Bucket<dht::ISNode>>(_local_key, llarp::randint);
    }

    std::optional<service::EncryptedIntroSet> Contacts::get_introset(RouterID remote) const
    {
        return get_introset(dht::Key_t::derive_from_rid(remote));
    }

    std::optional<service::EncryptedIntroSet> Contacts::get_introset(const dht::Key_t& key) const
    {
        std::optional<service::EncryptedIntroSet> enc = std::nullopt;

        auto& introsets = _introset_nodes->nodes;

        if (auto itr = introsets.find(key); itr != introsets.end())
            enc = itr->second.introset;

        return enc;
    }

    StatusObject Contacts::ExtractStatus() const
    {
        StatusObject obj{{"services", _introset_nodes->ExtractStatus()}, {"local_key", _local_key.ToHex()}};
        return obj;
    }

    void Contacts::put_intro(service::EncryptedIntroSet enc)
    {
        _introset_nodes->PutNode(std::move(enc));
    }

}  // namespace llarp
