#include "pathbuilder.hpp"

#include "path.hpp"
#include "path_context.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/link/link_manager.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/pathset.hpp>
#include <llarp/profiling.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging.hpp>

#include <functional>

namespace llarp
{
    namespace
    {
        auto path_cat = log::Cat("path");
    }

    namespace path
    {
        bool BuildLimiter::Attempt(const RouterID& router)
        {
            return _edge_limiter.Insert(router);
        }

        void BuildLimiter::Decay(llarp_time_t now)
        {
            _edge_limiter.Decay(now);
        }

        bool BuildLimiter::Limited(const RouterID& router) const
        {
            return _edge_limiter.Contains(router);
        }

        PathBuilder::PathBuilder(Router* p_router, size_t pathNum, size_t hops)
            : path::PathSet{pathNum}, _run{true}, router{p_router}, num_hops{hops}
        {}

        /* - For each hop:
         * SetupHopKeys:
         *   - Generate Ed keypair for the hop. ("commkey")
         *   - Use that key and the hop's pubkey for DH key exchange (makes "hop.shared")
         *     - Note: this *was* using hop's "enckey" but we're getting rid of that
         *   - hop's "upstream" RouterID is next hop, or that hop's ID if it is terminal hop
         *   - hop's chacha nonce is hash of symmetric key (hop.shared) from DH
         *   - hop's "txID" and "rxID" are chosen before this step
         *     - txID is the path ID for messages coming *from* the client/path origin
         *     - rxID is the path ID for messages going *to* it.
         *
         * CreateHopInfoFrame:
         *   - bt-encode "hop info":
         *     - path lifetime
         *     - protocol version
         *     - txID
         *     - rxID
         *     - nonce
         *     - upstream hop RouterID
         *     - ephemeral public key (for DH)
         *   - generate *second* ephemeral Ed keypair... ("framekey") TODO: why?
         *   - generate DH symmetric key using "framekey" and hop's pubkey
         *   - generate nonce for second encryption
         *   - encrypt "hop info" using this symmetric key
         *   - bt-encode nonce, "framekey" pubkey, encrypted "hop info"
         *   - hash this bt-encoded string
         *   - bt-encode hash and the frame in a dict, serialize
         *
         *
         *  all of these "frames" go in a list, along with any needed dummy frames
         */

        void PathBuilder::setup_hop_keys(path::PathHopConfig& hop, const RouterID& nextHop)
        {
            // generate key
            crypto::encryption_keygen(hop.commkey);

            hop.nonce.Randomize();
            // do key exchange
            if (!crypto::dh_client(hop.shared, hop.rc.router_id(), hop.commkey, hop.nonce))
            {
                auto err = fmt::format("{} failed to generate shared key for path build!", Name());
                log::error(path_cat, err);
                throw std::runtime_error{std::move(err)};
            }
            // generate nonceXOR value self->hop->pathKey
            ShortHash hash;
            crypto::shorthash(hash, hop.shared.data(), hop.shared.size());
            hop.nonceXOR = hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate

            hop.upstream = nextHop;
        }

        std::string PathBuilder::create_hop_info_frame(const path::PathHopConfig& hop)
        {
            std::string hop_info;

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("COMMKEY", hop.commkey.toPublic().ToView());
                btdp.append("LIFETIME", path::DEFAULT_LIFETIME.count());
                btdp.append("NONCE", hop.nonce.ToView());
                btdp.append("RX", hop.rxID.ToView());
                btdp.append("TX", hop.txID.ToView());
                btdp.append("UPSTREAM", hop.upstream.ToView());

                hop_info = std::move(btdp).str();
            }

            SecretKey framekey;
            crypto::encryption_keygen(framekey);

            SharedSecret shared;
            SymmNonce outer_nonce;
            outer_nonce.Randomize();

            // derive (outer) shared key
            if (!crypto::dh_client(shared, hop.rc.router_id(), framekey, outer_nonce))
            {
                log::error(path_cat, "DH client failed during hop info encryption!");
                throw std::runtime_error{"DH failed during hop info encryption"};
            }

            // encrypt hop_info (mutates in-place)
            if (!crypto::xchacha20(reinterpret_cast<uint8_t*>(hop_info.data()), hop_info.size(), shared, outer_nonce))
            {
                log::error(path_cat, "Hop info encryption failed!");
                throw std::runtime_error{"Hop info encrypttion failed"};
            }

            std::string hashed_data;

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("ENCRYPTED", hop_info);
                btdp.append("NONCE", outer_nonce.ToView());
                btdp.append("PUBKEY", framekey.toPublic().ToView());

                hashed_data = std::move(btdp).str();
            }

            std::string hash;
            hash.reserve(SHORTHASHSIZE);

            if (!crypto::hmac(
                    reinterpret_cast<uint8_t*>(hash.data()),
                    reinterpret_cast<uint8_t*>(hashed_data.data()),
                    hashed_data.size(),
                    shared))
            {
                log::error(path_cat, "Failed to generate HMAC for hop info");
                throw std::runtime_error{"Failed to generate HMAC for hop info"};
            }

            oxenc::bt_dict_producer btdp;

            btdp.append("FRAME", hashed_data);
            btdp.append("HASH", hash);

            return std::move(btdp).str();
        }

        void PathBuilder::ResetInternalState()
        {
            build_interval_limit = PATH_BUILD_RATE;
            _last_build = 0s;
        }

        void PathBuilder::Tick(llarp_time_t now)
        {
            PathSet::Tick(now);
            now = llarp::time_now_ms();
            router->pathbuild_limiter().Decay(now);

            ExpirePaths(now, router);
            if (ShouldBuildMore(now))
                BuildOne();
            TickPaths(router);
            if (build_stats.attempts > 50)
            {
                if (build_stats.SuccessRatio() <= BuildStats::MinGoodRatio && now - last_warn_time > 5s)
                {
                    LogWarn(Name(), " has a low path build success. ", build_stats);
                    last_warn_time = now;
                }
            }
        }

        util::StatusObject PathBuilder::ExtractStatus() const
        {
            util::StatusObject obj{
                {"buildStats", build_stats.ExtractStatus()},
                {"numHops", uint64_t{num_hops}},
                {"numPaths", uint64_t{num_paths_desired}}};
            std::transform(
                _paths.begin(),
                _paths.end(),
                std::back_inserter(obj["paths"]),
                [](const auto& item) -> util::StatusObject { return item.second->ExtractStatus(); });
            return obj;
        }

        std::optional<RemoteRC> PathBuilder::SelectFirstHop(const std::set<RouterID>& exclude) const
        {
            std::optional<RemoteRC> found = std::nullopt;
            router->for_each_connection([&](link::Connection& conn) {
                RouterID rid{conn.conn->remote_key()};

#ifndef TESTNET
                if (router->is_bootstrap_node(rid))
                    return;
#endif
                if (exclude.count(rid))
                    return;

                if (BuildCooldownHit(rid))
                    return;

                if (router->router_profiling().IsBadForPath(rid))
                    return;

                found = router->node_db()->get_rc(rid);
            });
            return found;
        }

        std::optional<std::vector<RemoteRC>> PathBuilder::GetHopsForBuild()
        {
            auto filter = [r = router](const RemoteRC& rc) -> bool {
                return not r->router_profiling().IsBadForPath(rc.router_id(), 1);
            };

            if (auto maybe = router->node_db()->get_random_rc_conditional(filter))
                return GetHopsAlignedToForBuild(maybe->router_id());

            return std::nullopt;
        }

        bool PathBuilder::Stop()
        {
            _run = false;
            // tell all our paths that they are to be ignored
            const auto now = Now();
            for (auto& item : _paths)
            {
                item.second->EnterState(PathStatus::IGNORE, now);
            }
            return true;
        }

        bool PathBuilder::IsStopped() const
        {
            return !_run.load();
        }

        bool PathBuilder::ShouldRemove() const
        {
            return IsStopped() and NumInStatus(PathStatus::ESTABLISHED) == 0;
        }

        bool PathBuilder::BuildCooldownHit(RouterID edge) const
        {
            return router->pathbuild_limiter().Limited(edge);
        }

        bool PathBuilder::BuildCooldownHit(llarp_time_t now) const
        {
            return now < _last_build + build_interval_limit;
        }

        bool PathBuilder::ShouldBuildMore(llarp_time_t now) const
        {
            if (IsStopped())
                return false;
            if (BuildCooldownHit(now))
                return false;
            return PathSet::ShouldBuildMore(now);
        }

        void PathBuilder::BuildOne(PathRole roles)
        {
            if (const auto maybe = GetHopsForBuild())
                Build(*maybe, roles);
        }

        bool PathBuilder::UrgentBuild(llarp_time_t) const
        {
            return build_interval_limit > MIN_PATH_BUILD_INTERVAL * 4;
        }

        std::optional<std::vector<RemoteRC>> PathBuilder::GetHopsAlignedToForBuild(
            RouterID endpoint, const std::set<RouterID>& exclude)
        {
            const auto pathConfig = router->config()->paths;

            std::vector<RemoteRC> hops;
            {
                const auto maybe = SelectFirstHop(exclude);
                if (not maybe.has_value())
                {
                    log::warning(path_cat, "{} has no first hop candidate", Name());
                    return std::nullopt;
                }
                hops.emplace_back(*maybe);
            };

            RemoteRC endpointRC;
            if (const auto maybe = router->node_db()->get_rc(endpoint))
            {
                endpointRC = *maybe;
            }
            else
                return std::nullopt;

            for (size_t idx = hops.size(); idx < num_hops; ++idx)
            {
                if (idx + 1 == num_hops)
                {
                    hops.emplace_back(endpointRC);
                }
                else
                {
                    auto filter = [&hops, r = router, endpointRC, pathConfig, exclude](const RemoteRC& rc) -> bool {
                        const auto& rid = rc.router_id();

                        if (exclude.count(rid))
                            return false;

                        std::set<RemoteRC> hopsSet;
                        hopsSet.insert(endpointRC);
                        hopsSet.insert(hops.begin(), hops.end());

                        if (r->router_profiling().IsBadForPath(rid, 1))
                            return false;

                        for (const auto& hop : hopsSet)
                        {
                            if (hop.router_id() == rid)
                                return false;
                        }

                        hopsSet.insert(rc);
#ifndef TESTNET
                        if (not pathConfig.check_rcs(hopsSet))
                            return false;
#endif
                        return rc.router_id() != endpointRC.router_id();
                    };

                    if (auto maybe = router->node_db()->get_random_rc_conditional(filter))
                        hops.emplace_back(*maybe);
                    else
                        return std::nullopt;
                }
            }
            return hops;
        }

        bool PathBuilder::BuildOneAlignedTo(const RouterID remote)
        {
            if (const auto maybe = GetHopsAlignedToForBuild(remote); maybe.has_value())
            {
                LogInfo(Name(), " building path to ", remote);
                Build(*maybe);
                return true;
            }
            return false;
        }

        llarp_time_t PathBuilder::Now() const
        {
            return router->now();
        }

        void PathBuilder::Build(std::vector<RemoteRC> hops, PathRole roles)
        {
            if (IsStopped())
            {
                log::info(path_cat, "Path builder is stopped, aborting path build...");
                return;
            }

            _last_build = llarp::time_now_ms();
            const auto& edge = hops[0].router_id();

            if (not router->pathbuild_limiter().Attempt(edge))
            {
                log::warning(path_cat, "{} building too quickly to edge router {}", Name(), edge);
                return;
            }

            std::string path_shortName = "[path " + router->ShortName() + "-";
            path_shortName = path_shortName + std::to_string(router->NextPathBuildNumber()) + "]";

            auto path = std::make_shared<path::Path>(router, hops, GetWeak(), roles, std::move(path_shortName));

            log::info(path_cat, "{} building path -> {} : {}", Name(), path->short_name(), path->HopsString());

            oxenc::bt_list_producer frames;
            std::vector<std::string> frame_str(path::MAX_LEN);
            auto& path_hops = path->hops;
            size_t n_hops = path_hops.size();
            size_t last_len{0};

            // each hop will be able to read the outer part of its frame and decrypt
            // the inner part with that information.  It will then do an onion step on the
            // remaining frames so the next hop can read the outer part of its frame,
            // and so on.  As this de-onion happens from hop 1 to n, we create and onion
            // the frames from hop n downto 1 (i.e. reverse order).  The first frame is
            // not onioned.
            //
            // Onion-ing the frames in this way will prevent relays controlled by
            // the same entity from knowing they are part of the same path
            // (unless they're adjacent in the path; nothing we can do about that obviously).

            // i from n_hops downto 0
            size_t i = n_hops;
            while (i > 0)
            {
                i--;
                bool lastHop = (i == (n_hops - 1));

                const auto& nextHop = lastHop ? path_hops[i].rc.router_id() : path_hops[i + 1].rc.router_id();

                PathBuildMessage::setup_hop_keys(path_hops[i], nextHop);
                frame_str[i] = PathBuildMessage::serialize(path_hops[i]);

                // all frames should be the same length...not sure what that is yet
                // it may vary if path lifetime is non-default, as that is encoded as an
                // integer in decimal, but it should be constant for a given path
                if (last_len != 0)
                    assert(frame_str[i].size() == last_len);

                last_len = frame_str[i].size();

                // onion each previously-created frame using the established shared secret and
                // onion_nonce = path_hops[i].nonce ^ path_hops[i].nonceXOR, which the transit hop
                // will have recovered after decrypting its frame.
                // Note: final value passed to crypto::onion is xor factor, but that's for *after*
                // the onion round to compute the return value, so we don't care about it.
                for (size_t j = n_hops - 1; j > i; j--)
                {
                    auto onion_nonce = path_hops[i].nonce ^ path_hops[i].nonceXOR;
                    crypto::onion(
                        reinterpret_cast<unsigned char*>(frame_str[j].data()),
                        frame_str[j].size(),
                        path_hops[i].shared,
                        onion_nonce,
                        onion_nonce);
                }
            }

            std::string dummy;
            dummy.reserve(last_len);
            // append dummy frames; path build request must always have MAX_LEN frames
            for (i = n_hops; i < path::MAX_LEN; i++)
            {
                frame_str[i].resize(last_len);
                randombytes(reinterpret_cast<uint8_t*>(frame_str[i].data()), frame_str[i].size());
            }

            for (auto& str : frame_str)  // NOLINT
            {
                frames.append(std::move(str));
            }

            router->path_context().AddOwnPath(GetSelf(), path);
            PathBuildStarted(path);

            // TODO:
            // Path build fail and success are handled poorly at best and changing how we
            // handle these responses as well as how we store and use Paths as a whole might
            // be worth doing sooner rather than later.  Leaving some TODOs below where fail
            // and success live.
            auto response_cb = [path](oxen::quic::message m) {
                if (m)
                {
                    // TODO: inform success (what this means needs revisiting, badly)
                    path->EnterState(path::PathStatus::ESTABLISHED);
                    return;
                }

                try
                {
                    // TODO: inform failure (what this means needs revisiting, badly)
                    if (m.timed_out)
                    {
                        log::warning(path_cat, "Path build request timed out!");
                        path->EnterState(path::PathStatus::TIMEOUT);
                    }
                    else
                    {
                        oxenc::bt_dict_consumer d{m.body()};
                        auto status = d.require<std::string_view>(messages::STATUS_KEY);
                        log::warning(path_cat, "Path build returned failure status: {}", status);
                        path->EnterState(path::PathStatus::FAILED);
                    }
                }
                catch (const std::exception& e)
                {
                    log::warning(path_cat, "Exception caught parsing path build response: {}", e.what());
                }
            };

            if (not router->send_control_message(
                    path->upstream(), "path_build", std::move(frames).str(), std::move(response_cb)))
            {
                log::warning(path_cat, "Error sending path_build control message");
                path->EnterState(path::PathStatus::FAILED, router->now());
            }
        }

        void PathBuilder::HandlePathBuilt(std::shared_ptr<Path> p)
        {
            build_interval_limit = PATH_BUILD_RATE;
            router->router_profiling().MarkPathSuccess(p.get());

            LogInfo(p->name(), " built latency=", to_string(p->intro.latency));
            build_stats.success++;
        }

        void PathBuilder::HandlePathBuildFailedAt(std::shared_ptr<Path> p, RouterID edge)
        {
            PathSet::HandlePathBuildFailedAt(p, edge);
            DoPathBuildBackoff();
        }

        void PathBuilder::DoPathBuildBackoff()
        {
            static constexpr std::chrono::milliseconds MaxBuildInterval = 30s;
            // linear backoff
            build_interval_limit = std::min(PATH_BUILD_RATE + build_interval_limit, MaxBuildInterval);
            LogWarn(Name(), " build interval is now ", to_string(build_interval_limit));
        }

        void PathBuilder::HandlePathBuildTimeout(std::shared_ptr<Path> p)
        {
            router->router_profiling().MarkPathTimeout(p.get());
            PathSet::HandlePathBuildTimeout(p);
            DoPathBuildBackoff();
        }

        void PathBuilder::ManualRebuild(size_t num, PathRole roles)
        {
            LogDebug(Name(), " manual rebuild ", num);
            while (num--)
                BuildOne(roles);
        }

    }  // namespace path
}  // namespace llarp
