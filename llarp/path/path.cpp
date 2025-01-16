#include "path.hpp"

#include <llarp/messages/dht.hpp>
#include <llarp/messages/exit.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/profiling.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/buffer.hpp>

#include <ranges>

namespace llarp::path
{
    static auto logcat = log::Cat("path");

    Path::Path(
        Router& rtr,
        const std::vector<RemoteRC>& hop_rcs,
        std::weak_ptr<PathHandler> _handler,
        bool is_session,
        bool is_client)
        : handler{std::move(_handler)},
          _router{rtr},
          _is_session_path{is_session},
          _is_client{is_client},
          num_hops{hop_rcs.size()}
    {
        populate_internals(hop_rcs);
        log::info(logcat, "Path successfully constructed: {}", to_string());
    }

    void Path::populate_internals(const std::vector<RemoteRC>& hop_rcs)
    {
        hops.resize(num_hops);

        for (size_t i = 0; i < num_hops; ++i)
        {
            /** Conditions:
                - First hop RXID is unique, the rest are the previous hop TXID
                - Last hop upstream is it's own RID, the rest are the next hop RID
                - First hop downstream is client's RID, the rest are the previous hop RID
                - Local hop RXID is random, TXID is first hop RXID
                - Local hop upstream is first hop RID, downstream is local instance RID
            */

            hops[i]._rid = hop_rcs[i].router_id();
            hops[i]._txid = HopID::make_random();

            if (i == 0)
            {
                hops[i]._rxid = HopID::make_random();
                hops[i]._upstream = hop_rcs[i + 1].router_id();
                hops[i]._downstream = _router.local_rid();
            }
            else if (i == num_hops - 1)
            {
                hops[i]._rxid = hops[i - 1]._txid;
                hops[i]._upstream = hops[i]._rid;
                hops[i]._downstream = hops[i - 1]._rid;
            }
            else
            {
                hops[i]._rxid = hops[i - 1]._txid;
                hops[i]._upstream = hop_rcs[i + 1].router_id();
                hops[i]._downstream = hops[i - 1]._rid;
            }

            // generate dh kx components
            hops[i].kx = shared_kx_data::generate();

            // Conditions written as ternaries
            // hops[i]._rxid = i ? hops[i - 1]._txid : HopID::make_random();
            // hops[i]._upstream = i == num_hops - 1 ? hops[i]._rid : hop_rcs[i + 1].router_id();
            // hops[i]._downstream = i ? hops[i - 1]._rid : _router.local_rid();
        }

        hops.back().terminal_hop = true;

        log::trace(logcat, "Path populated with hops: {}", hop_string());

        // initialize parts of the clientintro
        intro.pivot_rid = hops.back().router_id();
        intro.pivot_txid = hops.back()._txid;

        log::debug(
            logcat, "Path client intro holding pivot_rid ({}) and pivot_txid ({})", intro.pivot_rid, intro.pivot_txid);
    }

    void Path::link_session(session_tag t)
    {
        _linked_sessions.insert(t);
        log::critical(logcat, "Current path has {} linked sessions!", _linked_sessions.size());
        _is_session_path = true;
    }

    bool Path::unlink_session(session_tag t)
    {
        auto n = _linked_sessions.erase(t);
        _is_session_path = not _linked_sessions.empty();
        log::critical(logcat, "Current path has {} linked sessions!", _linked_sessions.size());
        return n != 0;
    }

    // void Path::recv_path_data_message(bstring data)
    // {
    //     if (_recv_dgram)
    //         _recv_dgram(std::move(data));
    //     else
    //         throw std::runtime_error{"Path does not have hook to receive datagrams!"};
    // }

    bool Path::operator<(const Path& other) const
    {
        auto& first_hop = hops.front();
        auto& other_first = other.hops.front();
        return std::tie(first_hop._txid, first_hop._rxid, first_hop._upstream)
            < std::tie(other_first._txid, other_first._rxid, other_first._upstream);
    }

    bool Path::operator==(const Path& other) const
    {
        bool ret = true;
        size_t len = std::min(hops.size(), other.hops.size()), i = 0;

        while (ret and i < len)
        {
            ret &= hops[i] == other.hops[i];
            ++i;
        };

        return ret;
    }

    bool Path::operator!=(const Path& other) const { return not(*this == other); }

    bool Path::obtain_exit(
        const Ed25519SecretKey& sk, uint64_t flag, std::string tx_id, std::function<void(oxen::quic::message)> func)
    {
        return send_path_control_message(
            "obtain_exit", ObtainExitMessage::sign_and_serialize(sk, flag, std::move(tx_id)), std::move(func));
    }

    bool Path::close_exit(const Ed25519SecretKey& sk, std::string tx_id, std::function<void(oxen::quic::message)> func)
    {
        return send_path_control_message(
            "close_exit", CloseExitMessage::sign_and_serialize(sk, std::move(tx_id)), std::move(func));
    }

    bool Path::find_client_contact(const dht::Key_t& location, std::function<void(oxen::quic::message)> func)
    {
        return send_path_control_message("find_cc", FindClientContact::serialize(location), std::move(func));
    }

    bool Path::publish_client_contact(const EncryptedClientContact& ecc, std::function<void(oxen::quic::message)> func)
    {
        return send_path_control_message("publish_cc", PublishClientContact::serialize(ecc), std::move(func));
    }

    bool Path::resolve_sns(std::string_view name, std::function<void(oxen::quic::message)> func)
    {
        return send_path_control_message("resolve_sns", ResolveSNS::serialize(name), std::move(func));
    }

    void Path::enable_exit_traffic() { log::info(logcat, "{} {} granted exit", name(), pivot_rid()); }

    void Path::mark_exit_closed() { log::info(logcat, "{} hd its exit closed", name()); }

    std::string Path::make_path_message(std::string inner_payload)
    {
        auto nonce = SymmNonce::make_random();

        for (const auto& hop : std::ranges::reverse_view(hops))
        {
            nonce = crypto::onion(
                reinterpret_cast<unsigned char*>(inner_payload.data()),
                inner_payload.size(),
                hop.kx.shared_secret,
                nonce,
                hop.kx.xor_nonce);
        }

        return ONION::serialize_hop(upstream_rxid().to_view(), nonce, std::move(inner_payload));
    }

    bool Path::send_path_data_message(std::string data)
    {
        auto inner_payload = PATH::DATA::serialize(std::move(data), _router.local_rid());
        auto outer_payload = make_path_message(std::move(inner_payload));
        return _router.send_data_message(upstream_rid(), std::move(outer_payload));
    }

    bool Path::send_path_control_message(
        std::string endpoint, std::string body, std::function<void(oxen::quic::message)> func)
    {
        auto inner_payload = PATH::CONTROL::serialize(std::move(endpoint), std::move(body));
        auto outer_payload = make_path_message(std::move(inner_payload));
        return _router.send_control_message(upstream_rid(), "path_control", std::move(outer_payload), std::move(func));
    }

    bool Path::is_ready(std::chrono::milliseconds now) const { return _established ? !is_expired(now) : false; }

    std::shared_ptr<PathHandler> Path::get_parent()
    {
        if (auto parent = handler.lock())
            return parent;

        return nullptr;
    }

    TransitHop Path::edge() const { return {hops.front()}; }

    RouterID Path::upstream_rid() { return hops.front().router_id(); }

    const RouterID& Path::upstream_rid() const { return hops.front().router_id(); }

    HopID Path::upstream_txid() { return hops.front().txid(); }

    const HopID& Path::upstream_txid() const { return hops.front().txid(); }

    HopID Path::upstream_rxid() { return hops.front().rxid(); }

    const HopID& Path::upstream_rxid() const { return hops.front().rxid(); }

    RouterID Path::pivot_rid() { return hops.back().router_id(); }

    const RouterID& Path::pivot_rid() const { return hops.back().router_id(); }

    HopID Path::pivot_txid() { return hops.back().txid(); }

    const HopID& Path::pivot_txid() const { return hops.back().txid(); }

    HopID Path::pivot_rxid() { return hops.back().rxid(); }

    const HopID& Path::pivot_rxid() const { return hops.back().rxid(); }

    std::string Path::to_string() const
    {
        return "Path:[ Local RID:{} -- Edge TX:{}/RX:{} ]"_format(
            _router.local_rid().ShortString(), upstream_txid().to_string(), upstream_rxid().to_string());
    }

    std::string Path::hop_string() const
    {
        std::string hops_str;
        hops_str.reserve(hops.size() * 62);  // 52 for the pkey, 6 for .snode, 4 for the ' -> ' joiner
        for (const auto& hop : hops)
        {
            if (!hops.empty())
                hops_str += " -> ";
            hops_str += hop.router_id().ShortString();
        }
        return hops_str;
    }

    nlohmann::json Path::ExtractStatus() const
    {
        auto now = llarp::time_now_ms();

        nlohmann::json obj{
            {"lastRecvMsg", to_json(last_recv_msg)},
            {"lastLatencyTest", to_json(last_latency_test)},
            {"expired", is_expired(now)},
            {"ready", is_ready()},
        };

        std::vector<nlohmann::json> hopsObj;
        std::transform(hops.begin(), hops.end(), std::back_inserter(hopsObj), [](const auto& hop) -> nlohmann::json {
            return hop.ExtractStatus();
        });
        obj["hops"] = hopsObj;

        return obj;
    }

    bool Path::update_exit(uint64_t)
    {
        // TODO: do we still want this concept?
        return false;
    }

    void Path::Tick(std::chrono::milliseconds now)
    {
        if (not is_ready())
            return;

        if (is_expired(now))
            return;

        if (_is_linked)
        {
        }
    }

    void Path::set_established()
    {
        log::info(logcat, "Path marked as successfully established!");
        _established = true;
        intro.expiry = llarp::time_now_ms() + path::DEFAULT_LIFETIME;
    }

    bool Path::is_expired(std::chrono::milliseconds now) const { return intro.is_expired(now); }

    std::string Path::name() const
    {
        return fmt::format("TX={} RX={}", upstream_txid().to_string(), upstream_rxid().to_string());
    }

    template <typename Samples_t>
    static std::chrono::milliseconds computeLatency(const Samples_t& samps)
    {
        std::chrono::milliseconds mean = 0s;
        if (samps.empty())
            return mean;
        for (const auto& samp : samps)
            mean += samp;
        return mean / samps.size();
    }
}  // namespace llarp::path
