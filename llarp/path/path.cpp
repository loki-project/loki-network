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
            hops[i]._rid = hop_rcs[i].router_id();
            hops[i]._txid = HopID::make_random();

            /** Conditions:
                - First hop RXID is unique, the rest are the previous hop TXID
                - Last hop upstream is it's own RID, the rest are the next hop RID
                - First hop downstream is client's RID, the rest are the previous hop RID
            */

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

            // Conditions written as ternaries
            // hops[i]._rxid = i ? hops[i - 1]._txid : HopID::make_random();
            // hops[i]._upstream = i == num_hops - 1 ? hops[i]._rid : hop_rcs[i + 1].router_id();
            // hops[i]._downstream = i ? hops[i - 1]._rid : _router.local_rid();
        }

        hops.back().terminal_hop = true;

        log::info(logcat, "Path populated with hops: {}", hop_string());

        // initialize parts of the clientintro
        intro.pivot_rid = hops.back().router_id();
        intro.pivot_rxid = hops.back()._rxid;

        log::debug(
            logcat, "Path client intro holding pivot_rid ({}) and pivot_rxid ({})", intro.pivot_rid, intro.pivot_rxid);
    }

    void Path::link_session(recv_session_dgram_cb cb)
    {
        _recv_dgram = std::move(cb);
        _is_session_path = true;
    }

    bool Path::unlink_session()
    {
        if (_is_linked)
        {
            _is_linked = false;
            _recv_dgram = nullptr;
            return true;
        }

        log::warning(logcat, "Path is not currently linked to an ongoing session!");
        return false;
    }

    void Path::recv_path_data_message(bstring data)
    {
        if (_recv_dgram)
            _recv_dgram(std::move(data));
        else
            throw std::runtime_error{"Path does not have hook to receive datagrams!"};
    }

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

    bool Path::operator!=(const Path& other) const
    {
        return not(*this == other);
    }

    bool Path::obtain_exit(
        const Ed25519SecretKey& sk, uint64_t flag, std::string tx_id, std::function<void(std::string)> func)
    {
        return send_path_control_message(
            "obtain_exit", ObtainExitMessage::sign_and_serialize(sk, flag, std::move(tx_id)), std::move(func));
    }

    bool Path::close_exit(const Ed25519SecretKey& sk, std::string tx_id, std::function<void(std::string)> func)
    {
        return send_path_control_message(
            "close_exit", CloseExitMessage::sign_and_serialize(sk, std::move(tx_id)), std::move(func));
    }

    bool Path::find_client_contact(
        const dht::Key_t& location, bool is_relayed, uint64_t order, std::function<void(std::string)> func)
    {
        return send_path_control_message(
            "find_cc", FindClientContact::serialize(location, order, is_relayed), std::move(func));
    }

    bool Path::publish_client_contact2(const EncryptedClientContact& ecc, std::function<void(oxen::quic::message)> func)
    {
        return send_path_control_message2("publish_cc", PublishClientContact::serialize(ecc), std::move(func));
    }

    bool Path::publish_client_contact(const EncryptedClientContact& ecc, std::function<void(std::string)> func)
    {
        return send_path_control_message("publish_cc_inner", PublishClientContact::serialize(ecc), std::move(func));
    }

    bool Path::resolve_ons(std::string name, std::function<void(std::string)> func)
    {
        return send_path_control_message("resolve_ons", FindNameMessage::serialize(std::move(name)), std::move(func));
    }

    void Path::enable_exit_traffic()
    {
        log::info(logcat, "{} {} granted exit", name(), pivot_rid());
        // _role |= ePathRoleExit;
    }

    void Path::mark_exit_closed()
    {
        log::info(logcat, "{} hd its exit closed", name());
        // _role &= ePathRoleExit;
    }

    std::string Path::make_path_message(std::string inner_payload)
    {
        auto nonce = SymmNonce::make_random();

        for (const auto& hop : std::ranges::reverse_view(hops))
        {
            nonce = crypto::onion(
                reinterpret_cast<unsigned char*>(inner_payload.data()),
                inner_payload.size(),
                hop.shared,
                nonce,
                hop.nonceXOR);
        }

        return ONION::serialize_hop(upstream_rxid().to_view(), nonce, std::move(inner_payload));
    }

    bool Path::send_path_data_message(std::string data)
    {
        auto inner_payload = PATH::DATA::serialize(std::move(data), _router.local_rid());
        auto outer_payload = make_path_message(std::move(inner_payload));

        return _router.send_data_message(upstream_rid(), std::move(outer_payload));
    }

    bool Path::send_path_control_message2(
        std::string endpoint, std::string body, std::function<void(oxen::quic::message)> func)
    {
        auto inner_payload = PATH::CONTROL::serialize(std::move(endpoint), std::move(body));
        auto outer_payload = make_path_message(std::move(inner_payload));

        return _router.send_control_message(upstream_rid(), "path_control", std::move(outer_payload), std::move(func));
    }

    bool Path::send_path_control_message(std::string endpoint, std::string body, std::function<void(std::string)> func)
    {
        auto inner_payload = PATH::CONTROL::serialize(std::move(endpoint), std::move(body));
        auto outer_payload = make_path_message(std::move(inner_payload));

        return _router.send_control_message(
            upstream_rid(),
            "path_control",
            std::move(outer_payload),
            [response_cb = std::move(func), weak = weak_from_this()](oxen::quic::message m) mutable {
                auto self = weak.lock();
                if (not self)
                {
                    log::warning(logcat, "Received response to path control message with non-existent path!");
                    return;
                }

                // TODO: DISCUSS: do we want to allow empty callback here?
                if (not response_cb)
                {
                    log::warning(logcat, "Received response to path control message with no response callback!");
                    return;
                }

                log::debug(logcat, "Received response to path control message: {}", buffer_printer{m.body()});

                if (m)
                    log::info(logcat, "Path control message returned successfully!");
                else if (m.timed_out)
                    log::warning(logcat, "Path control message returned as time out!");
                else
                    log::warning(logcat, "Path control message returned as error!");

                return response_cb(m.body_str());

                // TODO: onion encrypt path message responses
                // HopID hop_id;
                // SymmNonce nonce;
                // std::string payload;

                // try
                // {
                //     std::tie(hop_id, nonce, payload) = ONION::deserialize_hop(oxenc::bt_dict_consumer{m.body()});
                // }
                // catch (const std::exception& e)
                // {
                //     log::warning(logcat, "Exception parsing path control message response: {}", e.what());
                //     return response_cb(messages::ERROR_RESPONSE);
                // }

                // for (const auto& hop : self->hops)
                // {
                //     nonce = crypto::onion(
                //         reinterpret_cast<unsigned char*>(payload.data()),
                //         payload.size(),
                //         hop.shared,
                //         nonce,
                //         hop.nonceXOR);
                // }

                // // TODO: DISCUSS:
                // // Parsing and handling of the contents (errors, etc.) is the currently responsibility of the
                // callback response_cb(std::move(payload));
            });
    }

    bool Path::is_ready(std::chrono::milliseconds now) const
    {
        return _established ? !is_expired(now) : false;
    }

    std::shared_ptr<PathHandler> Path::get_parent()
    {
        if (auto parent = handler.lock())
            return parent;

        return nullptr;
    }

    RouterID Path::upstream_rid()
    {
        return hops.front().router_id();
    }

    const RouterID& Path::upstream_rid() const
    {
        return hops.front().router_id();
    }

    HopID Path::upstream_txid()
    {
        return hops.front().txid();
    }

    const HopID& Path::upstream_txid() const
    {
        return hops.front().txid();
    }

    HopID Path::upstream_rxid()
    {
        return hops.front().rxid();
    }

    const HopID& Path::upstream_rxid() const
    {
        return hops.front().rxid();
    }

    RouterID Path::pivot_rid()
    {
        return hops.back().router_id();
    }

    const RouterID& Path::pivot_rid() const
    {
        return hops.back().router_id();
    }

    HopID Path::pivot_txid()
    {
        return hops.back().txid();
    }

    const HopID& Path::pivot_txid() const
    {
        return hops.back().txid();
    }

    HopID Path::pivot_rxid()
    {
        return hops.back().rxid();
    }

    const HopID& Path::pivot_rxid() const
    {
        return hops.back().rxid();
    }

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

    void Path::rebuild()
    {
        if (auto parent = handler.lock())
        {
            auto prev_upstream_rxid = upstream_rxid();

            if (auto new_hops = parent->aligned_hops_to_remote(pivot_rid()))
            {
                populate_internals(*new_hops);
                log::info(logcat, "{} rebuilding new path to pivot {}", name(), to_string());

                auto self = shared_from_this();
                auto payload = parent->build2(self);
                auto upstream = upstream_rid();

                if (not parent->build3(
                        std::move(upstream),
                        std::move(payload),
                        [new_path = std::move(self), parent = parent, prev_rxid = prev_upstream_rxid](
                            oxen::quic::message m) mutable {
                            if (m)
                            {
                                log::critical(logcat, "PATH ESTABLISHED: {}", new_path->hop_string());
                                parent->drop_path(prev_rxid);
                                return parent->path_build_succeeded(std::move(new_path));
                            }

                            try
                            {
                                if (m.timed_out)
                                {
                                    log::warning(logcat, "Path build request timed out!");
                                }
                                else
                                {
                                    oxenc::bt_dict_consumer d{m.body()};
                                    auto status = d.require<std::string_view>(messages::STATUS_KEY);
                                    log::warning(logcat, "Path build returned failure status: {}", status);
                                }
                            }
                            catch (const std::exception& e)
                            {
                                log::warning(
                                    logcat,
                                    "Exception caught parsing path build response: {}; input: {}",
                                    e.what(),
                                    m.body());
                            }

                            parent->path_build_failed(std::move(new_path), m.timed_out);
                        }))
                {
                    log::warning(logcat, "Error sending path_build control message");
                }
            }
            else
            {
                log::warning(logcat, "Could not find new hops to rebuild path to pivot {}", to_string());
            }

            parent->drop_path(prev_upstream_rxid);
        }
        else
        {
            log::warning(logcat, "Path ({}) died with no parent to rebuild!", to_string());
        }
    }

    bool Path::SendLatencyMessage(Router*)
    {
        // const auto now = r->now();
        // // send path latency test
        // routing::PathLatencyMessage latency{};
        // latency.sent_time = randint();
        // latency.sequence_number = NextSeqNo();
        // m_LastLatencyTestID = latency.sent_time;
        // m_LastLatencyTestTime = now;
        // LogDebug(name(), " send latency test id=", latency.sent_time);
        // if (not SendRoutingMessage(latency, r))
        //   return false;
        // FlushUpstream(r);
        return true;
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

        // m_LastRXRate = m_RXRate;
        // m_LastTXRate = m_TXRate;

        // m_RXRate = 0;
        // m_TXRate = 0;

        // if (_status == PathStatus::BUILDING)
        // {
        //   if (buildStarted == 0s)
        //     return;
        //   if (now >= buildStarted)
        //   {
        //     const auto dlt = now - buildStarted;
        //     if (dlt >= path::BUILD_TIMEOUT)
        //     {
        //       LogWarn(name(), " waited for ", to_string(dlt), " and no path was built");
        //       r->router_profiling().MarkPathFail(this);
        //       EnterState(PathStatus::EXPIRED, now);
        //       return;
        //     }
        //   }
        // }
        // check to see if this path is dead
        // if (_status == PathStatus::ESTABLISHED)
        // {
        //   auto dlt = now - last_latency_test;
        //   if (dlt > path::LATENCY_INTERVAL && last_latency_test_id == 0)
        //   {
        //     SendLatencyMessage(r);
        //     // latency test FEC
        //     r->loop()->call_later(2s, [self = shared_from_this(), r]() {
        //       if (self->last_latency_test_id)
        //         self->SendLatencyMessage(r);
        //     });
        //     return;
        //   }
        //   dlt = now - last_recv_msg;
        //   if (dlt >= path::ALIVE_TIMEOUT)
        //   {
        //     LogWarn(name(), " waited for ", to_string(dlt), " and path looks dead");
        //     r->router_profiling().MarkPathFail(this);
        //     EnterState(PathStatus::TIMEOUT, now);
        //   }
        // }
        // if (_status == PathStatus::IGNORE and now - last_recv_msg >= path::ALIVE_TIMEOUT)
        // {
        //   // clean up this path as we dont use it anymore
        //   EnterState(PathStatus::EXPIRED, now);
        // }
    }

    /// how long we wait for a path to become active again after it times out
    // constexpr auto PathReanimationTimeout = 45s;

    void Path::set_established()
    {
        log::info(logcat, "Path marked as successfully established!");
        _established = true;
        intro.expiry = llarp::time_now_ms() + path::DEFAULT_LIFETIME;
    }

    bool Path::is_expired(std::chrono::milliseconds now) const
    {
        return intro.is_expired(now);
    }

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
