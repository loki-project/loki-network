#include "contactdb.hpp"

#include <llarp/router/router.hpp>

namespace llarp
{
    static auto logcat = log::Cat("contactdb");

    ContactDB::ContactDB(Router& r)
        : _router{r}, _local_key{hash_key::derive_from_rid(r.local_rid())}, _storage{XorMetric{_local_key}}
    {}

    std::optional<ClientContact> ContactDB::get_decrypted_cc(RouterID remote) const
    {
        std::optional<ClientContact> ret = std::nullopt;

        if (auto enc = get_encrypted_cc(hash_key::derive_from_rid(remote)))
            ret = enc->decrypt(remote);

        return ret;
    }

    std::optional<EncryptedClientContact> ContactDB::get_encrypted_cc(const hash_key& key) const
    {
        std::optional<EncryptedClientContact> enc = std::nullopt;

        if (auto it = _storage.find(key); it != _storage.end() && not it->second.is_expired())
            enc = it->second;

        return enc;
    }

    size_t ContactDB::num_ccs() const { return _storage.size(); }

    void ContactDB::start_tickers()
    {
        _router.loop()->call_later(approximate_time(5s, 5), [&]() {
            purge_ccs();
            log::debug(logcat, "ContactDB starting purge ticker..");
            _purge_ticker = _router.loop()->call_every(
                5min, [this]() mutable { purge_ccs(); }, true);
        });
    }

    void ContactDB::purge_ccs(std::chrono::milliseconds now)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "ContactDB unable to continue purge ticking -- router is stopped!");
            return;
        }

        size_t n = 0;

        for (auto it = _storage.begin(); it != _storage.end();)
        {
            if (it->second.is_expired(now))
            {
                it = _storage.erase(it);
                n += 1;
            }
            else
                ++it;
        }

        if (n)
            log::info(logcat, "{} expired ClientContacts purged!", n);
    }

    void ContactDB::put_cc(EncryptedClientContact enc)
    {
        auto key = hash_key{enc.blinded_pubkey};

        if (auto it = _storage.find(key); it == _storage.end() || it->second < enc)
            _storage[key] = std::move(enc);
    }

}  //  namespace llarp
