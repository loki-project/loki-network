#pragma once

#include "client_contact.hpp"

#include <llarp/ev/types.hpp>

namespace llarp
{
    struct Router;

    /**
        ContactDB TODO:
        - Store nearest-furthest expiry, trim
    */

    using cc_map_storage = std::map<hash_key, EncryptedClientContact, XorMetric>;

    /// This class mediates storage, retrieval, and functionality for ClientContacts
    struct ContactDB
    {
        explicit ContactDB(Router& r);

      private:
        Router& _router;
        const hash_key _local_key;

        cc_map_storage _storage;

        std::shared_ptr<EventTicker> _purge_ticker;

      public:
        std::optional<ClientContact> get_decrypted_cc(RouterID remote) const;

        std::optional<EncryptedClientContact> get_encrypted_cc(const hash_key& key) const;

        void put_cc(EncryptedClientContact enc);

        void start_tickers();

        size_t num_ccs() const;

      private:
        void purge_ccs(std::chrono::milliseconds now = llarp::time_now_ms());
    };

}  // namespace llarp
