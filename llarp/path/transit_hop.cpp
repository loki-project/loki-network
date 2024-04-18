#include "transit_hop.hpp"

#include <llarp/messages/path.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/time.hpp>

namespace llarp::path
{
    static auto logcat = log::Cat("transit-hop");

    std::shared_ptr<TransitHop> TransitHop::deserialize_hop(
        oxenc::bt_dict_consumer& btdc, const RouterID& src, Router& r, ustring symmkey, ustring symmnonce)
    {
        std::shared_ptr<TransitHop> hop;

        try
        {
            hop->lifetime = btdc.require<uint64_t>("l") * 1ms;
            hop->rxID().from_string(btdc.require<std::string_view>("r"));
            hop->txID().from_string(btdc.require<std::string_view>("t"));
            hop->upstream().from_string(btdc.require<std::string_view>("u"));
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "TransitHop caught bt parsing exception:{}", e.what());
            throw std::runtime_error{messages::ERROR_RESPONSE};
        }

        if (hop->rxID().is_zero() || hop->txID().is_zero())
            throw std::runtime_error{PathBuildMessage::BAD_PATHID};

        if (hop->lifetime >= path::DEFAULT_LIFETIME)
            throw std::runtime_error{PathBuildMessage::BAD_LIFETIME};

        hop->downstream() = src;

        if (r.path_context()->has_transit_hop(hop))
            throw std::runtime_error{PathBuildMessage::BAD_PATHID};

        if (!crypto::dh_server(hop->shared.data(), symmkey.data(), r.pubkey().data(), symmnonce.data()))
            throw std::runtime_error{PathBuildMessage::BAD_CRYPTO};

        // generate hash of hop key for nonce mutation
        ShortHash xor_hash;
        crypto::shorthash(xor_hash, hop->shared.data(), hop->shared.size());
        hop->nonceXOR = xor_hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate

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
