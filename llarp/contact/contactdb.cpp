#include "contactdb.hpp"

#include <llarp/router/router.hpp>

namespace llarp
{
    ContactDB::ContactDB(Router& r) : _router{r}, _local_key{dht::Key_t::derive_from_rid(r.local_rid())}
    {
        timer_keepalive = std::make_shared<int>(0);
        _cc_nodes = std::make_unique<dht::Bucket<dht::CCNode>>(_local_key, csrng);
    }

    std::optional<ClientContact> ContactDB::get_decrypted_cc(RouterID remote) const
    {
        std::optional<ClientContact> ret = std::nullopt;

        if (auto enc = get_encrypted_cc(dht::Key_t::derive_from_rid(remote)))
            ret = enc->decrypt(remote);

        return ret;
    }

    std::optional<EncryptedClientContact> ContactDB::get_encrypted_cc(const dht::Key_t& key) const
    {
        std::optional<EncryptedClientContact> enc = std::nullopt;

        auto& clientcontacts = _cc_nodes->nodes;

        if (auto itr = clientcontacts.find(key); itr != clientcontacts.end() && not itr->second.ecc.is_expired())
            enc = itr->second.ecc;

        return enc;
    }

    nlohmann::json ContactDB::ExtractStatus() const
    {
        nlohmann::json obj{{"known_client_intros", _cc_nodes->ExtractStatus()}, {"local_key", _local_key.ToHex()}};
        return obj;
    }

    void ContactDB::put_cc(EncryptedClientContact enc) { _cc_nodes->put_node(enc); }

}  //  namespace llarp
