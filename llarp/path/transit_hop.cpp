#include "transit_hop.hpp"

#include <llarp/messages/path.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/time.hpp>

namespace llarp::path
{
    static auto logcat = log::Cat("transit-hop");

    TransitHopInfo::TransitHopInfo(RouterID down) : downstream{std::move(down)}
    {}

    std::shared_ptr<TransitHop> TransitHop::deserialize_hop(
        oxenc::bt_dict_consumer& btdc, const RouterID& src, Router& r, ustring symmkey, ustring symmnonce)
    {
        std::shared_ptr<TransitHop> hop;

        uint64_t lifetime;
        std::string rx_id, tx_id, upstream;

        try
        {
            lifetime = btdc.require<uint64_t>("l");
            rx_id = btdc.require<std::string>("r");
            tx_id = btdc.require<std::string>("t");
            upstream = btdc.require<std::string>("u");
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "TransitHop caught bt parsing exception:{}", e.what());
            throw std::runtime_error{messages::ERROR_RESPONSE};
        }

        hop->info.txID.from_string(tx_id);
        hop->info.rxID.from_string(rx_id);

        if (hop->info.rxID.is_zero() || hop->info.txID.is_zero())
            throw std::runtime_error{PathBuildMessage::BAD_PATHID};

        hop->info.downstream = src;
        hop->info.upstream.from_snode_address(upstream);

        if (r.path_context().has_transit_hop(hop->info))
            throw std::runtime_error{PathBuildMessage::BAD_PATHID};

        if (!crypto::dh_server(hop->shared.data(), symmkey.data(), r.pubkey(), symmnonce.data()))
            throw std::runtime_error{PathBuildMessage::BAD_CRYPTO};

        // generate hash of hop key for nonce mutation
        ShortHash xor_hash;
        crypto::shorthash(xor_hash, hop->shared.data(), hop->shared.size());
        hop->nonceXOR = xor_hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate

        if (hop->lifetime = 1ms * lifetime; hop->lifetime >= path::DEFAULT_LIFETIME)
            throw std::runtime_error{PathBuildMessage::BAD_LIFETIME};

        return hop;
    }

    std::string TransitHopInfo::to_string() const
    {
        return fmt::format("[TransitHopInfo tx={} rx={} upstream={} downstream={}]", txID, rxID, upstream, downstream);
    }

    bool TransitHop::is_expired(std::chrono::milliseconds now) const
    {
        return destroy || (now >= ExpireTime());
    }

    std::chrono::milliseconds TransitHop::ExpireTime() const
    {
        return started + lifetime;
    }

    std::string TransitHop::to_string() const
    {
        return fmt::format("[TransitHop {} started={} lifetime={}", info, started.count(), lifetime.count());
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
