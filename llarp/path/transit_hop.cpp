#include "transit_hop.hpp"

#include <llarp/messages/path.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/time.hpp>

namespace llarp::path
{
    static auto logcat = log::Cat("transit-hop");

    std::shared_ptr<TransitHop> TransitHop::deserialize_hop(
        oxenc::bt_dict_consumer&& btdc, const RouterID& src, Router& r, const PubKey& remote_pk, const SymmNonce& nonce)
    {
        auto hop = std::make_shared<TransitHop>();

        try
        {
            hop->lifetime = btdc.require<uint64_t>("l") * 1ms;
            hop->_rxid.from_string(btdc.require<std::string_view>("r"));
            hop->_txid.from_string(btdc.require<std::string_view>("t"));
            hop->_upstream.from_string(btdc.require<std::string_view>("u"));
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "TransitHop caught bt parsing exception:{}", e.what());
            throw std::runtime_error{messages::ERROR_RESPONSE};
        }

        if (hop->rxid().is_zero() || hop->txid().is_zero())
            throw std::runtime_error{PathBuildMessage::BAD_PATHID};

        if (hop->lifetime > path::DEFAULT_LIFETIME)
            throw std::runtime_error{PathBuildMessage::BAD_LIFETIME};

        hop->downstream() = src;

        if (r.path_context()->has_transit_hop(hop))
            throw std::runtime_error{PathBuildMessage::BAD_PATHID};

        // TODO: get this from the first dh
        if (!crypto::dh_server(hop->shared, remote_pk, r.identity(), nonce))
            throw std::runtime_error{PathBuildMessage::BAD_CRYPTO};

        // generate hash of hop key for nonce mutation
        ShortHash xor_hash;
        crypto::shorthash(xor_hash, hop->shared.data(), hop->shared.size());
        hop->nonceXOR = xor_hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate

        log::debug(logcat, "TransitHop data successfully deserialized");

        return hop;
    }

    bool TransitHop::is_expired(std::chrono::milliseconds now) const
    {
        return destroy || (now >= expiry_time());
    }

    std::chrono::milliseconds TransitHop::expiry_time() const
    {
        return started + lifetime;
    }

    std::string TransitHop::to_string() const
    {
        return "[TransitHop: tx={} rx={} upstream={} downstream={} started={} lifetime={}"_format(
            _txid, _rxid, _upstream, _downstream, started.count(), lifetime.count());
    }

    void TransitHop::Stop()
    {
        // TODO: still need this concept?
    }

    void TransitHop::SetSelfDestruct()
    {
        destroy = true;
    }

    void TransitHop::QueueDestroySelf(Router* r)
    {
        r->loop()->call([self = shared_from_this()] { self->SetSelfDestruct(); });
    }
}  // namespace llarp::path
