#include "path.hpp"

#include <llarp/messages/dht.hpp>
#include <llarp/messages/exit.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/profiling.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/buffer.hpp>

namespace llarp::path
{
    static auto logcat = log::Cat("path");

    Path::Path(Router& rtr, const std::vector<RemoteRC>& h, std::weak_ptr<PathHandler> pathset, bool is_session)
        : handler{std::move(pathset)}, _router{rtr}, _is_session_path{is_session}
    {
        hops.resize(h.size());
        size_t hsz = h.size();
        for (size_t idx = 0; idx < hsz; ++idx)
        {
            hops[idx].rc = h[idx];
            do
            {
                hops[idx].txID.Randomize();
            } while (hops[idx].txID.is_zero());

            do
            {
                hops[idx].rxID.Randomize();
            } while (hops[idx].rxID.is_zero());
        }

        for (size_t idx = 0; idx < hsz - 1; ++idx)
        {
            hops[idx].txID = hops[idx + 1].rxID;
        }

        // initialize parts of the introduction
        intro.pivot_router = hops[hsz - 1].rc.router_id();
        intro.hop_id = hops[hsz - 1].txID;
    }

    bool Path::operator<(const Path& other) const
    {
        auto& first_hop = hops[0];
        auto& other_first = other.hops[0];
        return std::tie(first_hop.txID, first_hop.rxID, first_hop.upstream)
            < std::tie(other_first.txID, other_first.rxID, other_first.upstream);
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

    bool Path::obtain_exit(SecretKey sk, uint64_t flag, std::string tx_id, std::function<void(std::string)> func)
    {
        return send_path_control_message(
            "obtain_exit", ObtainExitMessage::sign_and_serialize(sk, flag, std::move(tx_id)), std::move(func));
    }

    bool Path::close_exit(SecretKey sk, std::string tx_id, std::function<void(std::string)> func)
    {
        return send_path_control_message(
            "close_exit", CloseExitMessage::sign_and_serialize(sk, std::move(tx_id)), std::move(func));
    }

    bool Path::find_intro(
        const dht::Key_t& location, bool is_relayed, uint64_t order, std::function<void(std::string)> func)
    {
        return send_path_control_message(
            "find_intro", FindIntroMessage::serialize(location, is_relayed, order), std::move(func));
    }

    bool Path::resolve_ons(std::string name, std::function<void(std::string)> func)
    {
        return send_path_control_message("resolve_ons", FindNameMessage::serialize(std::move(name)), std::move(func));
    }

    void Path::enable_exit_traffic()
    {
        log::info(logcat, "{} {} granted exit", name(), pivot_router_id().to_string());
        // _role |= ePathRoleExit;
    }

    void Path::mark_exit_closed()
    {
        log::info(logcat, "{} hd its exit closed", name());
        // _role &= ePathRoleExit;
    }

    std::string Path::make_outer_payload(ustring_view payload, SymmNonce& nonce)
    {
        // chacha and mutate nonce for each hop
        for (const auto& hop : hops)
        {
            nonce = crypto::onion(
                const_cast<unsigned char*>(payload.data()), payload.size(), hop.shared, nonce, hop.nonceXOR);
        }

        return Onion::serialize(nonce, TXID(), payload);
    }

    std::string Path::make_outer_payload(ustring_view payload)
    {
        auto nonce = SymmNonce::make_random();

        return make_outer_payload(payload, nonce);
    }

    bool Path::send_path_data_message(std::string body)
    {
        auto payload = PathData::serialize(std::move(body));
        auto outer_payload = make_outer_payload(to_usv(payload));

        return _router.send_data_message(upstream(), std::move(outer_payload));
    }

    bool Path::send_path_control_message(std::string method, std::string body, std::function<void(std::string)> func)
    {
        auto payload = PathControl::serialize(std::move(method), std::move(body));
        auto outer_payload = make_outer_payload(to_usv(payload));

        return _router.send_control_message(
            upstream(),
            "path_control",
            std::move(outer_payload),
            [response_cb = std::move(func), weak = weak_from_this()](oxen::quic::message m) {
                auto self = weak.lock();
                // TODO: do we want to allow empty callback here?
                if ((not self) or (not response_cb))
                    return;

                if (m.timed_out)
                {
                    response_cb(messages::TIMEOUT_RESPONSE);
                    return;
                }

                ustring hop_id_str, symmnonce, payload;

                try
                {
                    oxenc::bt_dict_consumer btdc{m.body()};
                    std::tie(hop_id_str, symmnonce, payload) = Onion::deserialize(btdc);
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Error parsing path control message response: {}", e.what());
                    response_cb(messages::ERROR_RESPONSE);
                    return;
                }

                SymmNonce nonce{symmnonce.data()};

                for (const auto& hop : self->hops)
                {
                    nonce = crypto::onion(
                        reinterpret_cast<unsigned char*>(payload.data()),
                        payload.size(),
                        hop.shared,
                        nonce,
                        hop.nonceXOR);
                }

                // TODO: should we do anything (even really simple) here to check if the decrypted
                //       response is sensible (e.g. is a bt dict)?  Parsing and handling of the
                //       contents (errors or otherwise) is the currently responsibility of the
                //       callback.
                response_cb(std::string{reinterpret_cast<const char*>(payload.data()), payload.size()});
            });
    }

    const RouterID& Path::pivot_router_id() const
    {
        return intro.pivot_router;
    }

    HopID Path::TXID() const
    {
        return hops[0].txID;
    }

    HopID Path::RXID() const
    {
        return hops[0].rxID;
    }

    bool Path::IsReady() const
    {
        if (is_expired(llarp::time_now_ms()))
            return false;
        return intro.latency > 0s && _established;
    }

    RouterID Path::upstream() const
    {
        return hops[0].rc.router_id();
    }

    RouterID Path::terminus() const
    {
        return hops.back().rc.router_id();
    }

    std::string Path::to_string() const
    {
        return "RID:{} -- TX:{}/RX:{}"_format(_router.local_rid(), TXID().to_view(), RXID().to_view());
    }

    std::string Path::HopsString() const
    {
        std::string hops_str;
        hops_str.reserve(hops.size() * 62);  // 52 for the pkey, 6 for .snode, 4 for the ' -> ' joiner
        for (const auto& hop : hops)
        {
            if (!hops.empty())
                hops_str += " -> ";
            hops_str += hop.rc.router_id().to_view();
        }
        return hops_str;
    }

    StatusObject PathHopConfig::ExtractStatus() const
    {
        StatusObject obj{
            {"ip", rc.addr().to_string()},
            {"lifetime", to_json(lifetime)},
            {"router", rc.router_id().ToHex()},
            {"txid", txID.ToHex()},
            {"rxid", rxID.ToHex()}};
        return obj;
    }

    StatusObject Path::ExtractStatus() const
    {
        auto now = llarp::time_now_ms();

        StatusObject obj{
            {"intro", intro.ExtractStatus()},
            {"lastRecvMsg", to_json(last_recv_msg)},
            {"lastLatencyTest", to_json(last_latency_test)},
            {"buildStarted", to_json(buildStarted)},
            {"expired", is_expired(now)},
            {"expiresSoon", ExpiresSoon(now)},
            {"expiresAt", to_json(ExpireTime())},
            {"ready", IsReady()},
            // {"txRateCurrent", m_LastTXRate},
            // {"rxRateCurrent", m_LastRXRate},
            // {"hasExit", SupportsAnyRoles(ePathRoleExit)}
        };

        std::vector<StatusObject> hopsObj;
        std::transform(hops.begin(), hops.end(), std::back_inserter(hopsObj), [](const auto& hop) -> StatusObject {
            return hop.ExtractStatus();
        });
        obj["hops"] = hopsObj;

        // switch (_status)
        // {
        //   case PathStatus::BUILDING:
        //     obj["status"] = "building";
        //     break;
        //   case PathStatus::ESTABLISHED:
        //     obj["status"] = "established";
        //     break;
        //   case PathStatus::TIMEOUT:
        //     obj["status"] = "timeout";
        //     break;
        //   case PathStatus::EXPIRED:
        //     obj["status"] = "expired";
        //     break;
        //   case PathStatus::FAILED:
        //     obj["status"] = "failed";
        //     break;
        //   case PathStatus::IGNORE:
        //     obj["status"] = "ignored";
        //     break;
        //   default:
        //     obj["status"] = "unknown";
        //     break;
        // }
        return obj;
    }

    void Path::rebuild()
    {
        if (auto parent = handler.lock())
        {
            std::vector<RemoteRC> new_hops;

            for (const auto& hop : hops)
                new_hops.emplace_back(hop.rc);

            log::info(logcat, "{} rebuilding on {}", name(), to_string());
            parent->build(new_hops);
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

    void Path::Tick(std::chrono::milliseconds now, Router* r)
    {
        (void)r;

        if (is_expired(now))
            return;

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

    bool Path::is_expired(std::chrono::milliseconds now) const
    {
        (void)now;
        // if (_status == PathStatus::FAILED)
        //   return true;
        // if (_status == PathStatus::BUILDING)
        //   return false;
        // if (_status == PathStatus::TIMEOUT)
        // {
        //   return now >= last_recv_msg + PathReanimationTimeout;
        // }
        // if (_status == PathStatus::ESTABLISHED or _status == PathStatus::IGNORE)
        // {
        //   return now >= ExpireTime();
        // }
        return true;
    }

    std::string Path::name() const
    {
        return fmt::format("TX={} RX={}", TXID().to_string(), RXID().to_string());
    }

    /* TODO: replace this with sending an onion-ed data message
    bool Path::SendRoutingMessage(std::string payload, Router*)
    {
      std::string buf(MAX_LINK_MSG_SIZE / 2, '\0');
      buf.insert(0, payload);

      // make nonce
      TunnelNonce N;
      N.Randomize();

      // pad smaller messages
      if (payload.size() < PAD_SIZE)
      {
        // randomize padding
        crypto::randbytes(
            reinterpret_cast<unsigned char*>(buf.data()) + payload.size(), PAD_SIZE -
    payload.size());
      }
      log::debug(logcat, "Sending {}B routing message to {}", buf.size(), Endpoint());

      // TODO: path relaying here

      return true;
    }
    */

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
