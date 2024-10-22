#pragma once

#include <llarp/dht/bucket.hpp>
#include <llarp/dht/node.hpp>

namespace llarp
{
    struct Router;

    /**
        ContactDB TODO:
        - Store nearest-furthest expiry, trim
    */

    /// This class mediates storage, retrieval, and functionality for ClientContacts
    struct ContactDB
    {
      private:
        std::shared_ptr<int> timer_keepalive;
        Router& _router;
        const dht::Key_t _local_key;

        std::unique_ptr<dht::Bucket<dht::CCNode>> _cc_nodes;

      public:
        explicit ContactDB(Router& r);

        std::optional<ClientContact> get_decrypted_cc(RouterID remote) const;

        std::optional<EncryptedClientContact> get_encrypted_cc(const dht::Key_t& key) const;

        nlohmann::json ExtractStatus() const;

        void put_cc(EncryptedClientContact enc);

        Router* router() const { return &_router; }
    };

}  // namespace llarp
