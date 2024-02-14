#include "transit_hop.hpp"

#include <llarp/router/router.hpp>
#include <llarp/util/buffer.hpp>

namespace llarp::path
{
    std::string TransitHopInfo::to_string() const
    {
        return fmt::format("[TransitHopInfo tx={} rx={} upstream={} downstream={}]", txID, rxID, upstream, downstream);
    }

    TransitHop::TransitHop() : AbstractHopHandler{}
    {}

    void TransitHop::onion(ustring& data, SymmNonce& nonce, bool randomize) const
    {
        if (randomize)
            nonce.Randomize();
        nonce = crypto::onion(data.data(), data.size(), pathKey, nonce, nonceXOR);
    }

    void TransitHop::onion(std::string& data, SymmNonce& nonce, bool randomize) const
    {
        if (randomize)
            nonce.Randomize();
        nonce = crypto::onion(reinterpret_cast<unsigned char*>(data.data()), data.size(), pathKey, nonce, nonceXOR);
    }

    std::string TransitHop::onion_and_payload(std::string& payload, HopID next_id, std::optional<SymmNonce> nonce) const
    {
        SymmNonce n;
        auto& nref = nonce ? *nonce : n;
        onion(payload, nref, not nonce);

        return make_onion_payload(nref, next_id, payload);
    }

    // TODO: if we want terminal/pivot hops to be able to *initiate* a request rather than
    //       simply responding/reacting to the client end's requests, these will need
    //       an implementation.
    bool TransitHop::send_path_control_message(std::string, std::string, std::function<void(std::string)>)
    {
        return true;
    }
    bool TransitHop::send_path_data_message(std::string)
    {
        return true;
    }

    bool TransitHop::is_expired(llarp_time_t now) const
    {
        return destroy || (now >= ExpireTime());
    }

    llarp_time_t TransitHop::ExpireTime() const
    {
        return started + lifetime;
    }

    TransitHopInfo::TransitHopInfo(RouterID down) : downstream{std::move(down)}
    {}

    /* TODO: replace this with layer of onion + send data message
    bool TransitHop::SendRoutingMessage(std::string payload, Router* r)
    {
      if (!IsEndpoint(r->pubkey()))
        return false;

      TunnelNonce N;
      N.Randomize();
      // pad to nearest MESSAGE_PAD_SIZE bytes
      auto dlt = payload.size() % PAD_SIZE;

      if (dlt)
      {
        dlt = PAD_SIZE - dlt;
        // randomize padding
        crypto::randbytes(reinterpret_cast<uint8_t*>(payload.data()), dlt);
      }

      // TODO: relay message along

      return true;
    }
    */

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
