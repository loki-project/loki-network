#include "server.hpp"

#include "nm_platform.hpp"
#include "sd_platform.hpp"

#include <llarp/constants/apple.hpp>
#include <llarp/constants/platform.hpp>
#include <llarp/ev/udp_handle.hpp>

#include <oxen/log.hpp>
#include <unbound.h>
#include <uvw.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

namespace llarp::dns
{
    static auto logcat = log::Cat("dns");

    void QueryJob_Base::cancel()
    {
        Message reply{_query};
        reply.add_srv_fail();
        send_reply(reply.to_buffer());
    }

    /// sucks up udp packets from a bound socket and feeds it to a server
    class UDPReader : public PacketSource_Base, public std::enable_shared_from_this<UDPReader>
    {
        Server& _dns;
        std::shared_ptr<llarp::UDPHandle_deprecated> _udp;
        oxen::quic::Address _local_addr;

       public:
        explicit UDPReader(Server& dns, const std::shared_ptr<EvLoop_deprecated>& loop, oxen::quic::Address bindaddr)
            : _dns{dns}
        {
            _udp = loop->make_udp([&](auto&, oxen::quic::Address src, llarp::OwnedBuffer buf) {
                if (src == _local_addr)
                    return;
                if (not _dns.maybe_handle_packet(shared_from_this(), _local_addr, src, std::move(buf)))
                {
                    log::warning(logcat, "did not handle dns packet from {} to {}", src, _local_addr);
                }
            });
            _udp->listen(bindaddr);
            if (auto maybe_addr = bound_on())
            {
                _local_addr = *maybe_addr;
            }
            else
                throw std::runtime_error{"cannot find which address our dns socket is bound on"};
        }

        std::optional<SockAddr_deprecated> bound_on() const override
        {
            return _udp->LocalAddr();
        }

        bool would_loop(const SockAddr_deprecated& to, const SockAddr_deprecated&) const override
        {
            return to != _local_addr;
        }

        void send_to(const SockAddr_deprecated& to, const SockAddr_deprecated&, llarp::OwnedBuffer buf) const override
        {
            _udp->send(to, std::move(buf));
        }

        void stop() override
        {
            _udp->close();
        }
    };

    namespace libunbound
    {
        class Resolver;

        class Query : public QueryJob_Base, public std::enable_shared_from_this<Query>
        {
            std::shared_ptr<PacketSource_Base> src;
            SockAddr_deprecated resolverAddr;
            SockAddr_deprecated askerAddr;

           public:
            explicit Query(
                std::weak_ptr<Resolver> parent_,
                Message query,
                std::shared_ptr<PacketSource_Base> pktsrc,
                SockAddr_deprecated toaddr,
                SockAddr_deprecated fromaddr)
                : QueryJob_Base{std::move(query)},
                  src{std::move(pktsrc)},
                  resolverAddr{std::move(toaddr)},
                  askerAddr{std::move(fromaddr)},
                  parent{parent_}
            {}
            std::weak_ptr<Resolver> parent;
            int id{};

            void send_reply(llarp::OwnedBuffer replyBuf) override;
        };

        /// Resolver_Base that uses libunbound
        class Resolver final : public Resolver_Base, public std::enable_shared_from_this<Resolver>
        {
            ub_ctx* m_ctx = nullptr;
            std::weak_ptr<EvLoop_deprecated> _loop;
#ifdef _WIN32
            // windows is dumb so we do ub mainloop in a thread
            std::thread runner;
            std::atomic<bool> running;
#else
            std::shared_ptr<uvw::PollHandle> _poller;
#endif

            std::optional<oxen::quic::Address> _local_addr;
            std::unordered_set<std::shared_ptr<Query>> _pending;

            struct ub_result_deleter
            {
                void operator()(ub_result* ptr)
                {
                    ::ub_resolve_free(ptr);
                }
            };

            const net::Platform* net_ptr() const
            {
                return _loop.lock()->net_ptr();
            }

            static void callback(void* data, int err, ub_result* _result)
            {
                log::debug(logcat, "got dns response from libunbound");
                // take ownership of ub_result
                std::unique_ptr<ub_result, ub_result_deleter> result{_result};
                // borrow query
                auto* query = static_cast<Query*>(data);
                if (err)
                {
                    // some kind of error from upstream
                    log::warning(logcat, "Upstream DNS failure: {}", ub_strerror(err));
                    query->cancel();
                    return;
                }

                log::trace(logcat, "queueing dns response from libunbound to userland");

                // rewrite response
                OwnedBuffer pkt{(const uint8_t*)result->answer_packet, (size_t)result->answer_len};
                llarp_buffer_t buf{pkt};
                MessageHeader hdr;
                hdr.Decode(&buf);
                hdr.id = query->underlying().hdr_id;
                buf.cur = buf.base;
                hdr.Encode(&buf);

                // send reply
                query->send_reply(std::move(pkt));
            }

            void add_upstream_resolver(const oxen::quic::Address& dns)
            {
                auto str = "{}@{}"_format(dns.host(), dns.port());

                if (auto err = ub_ctx_set_fwd(m_ctx, str.c_str()))
                {
                    throw std::runtime_error{fmt::format("cannot use {} as upstream dns: {}", str, ub_strerror(err))};
                }
            }

            bool configure_apple_trampoline(const oxen::quic::Address& dns)
            {
                // On Apple, when we turn on exit mode, we tear down and then reestablish the
                // unbound resolver: in exit mode, we set use upstream to a localhost trampoline
                // that redirects packets through the tunnel.  In non-exit mode, we directly use the
                // upstream, so we look here for a reconfiguration to use the trampoline port to
                // check which state we're in.
                //
                // We have to do all this crap because we can't directly connect to upstream from
                // here: within the network extension, macOS ignores the tunnel we are managing and
                // so, if we didn't do this, all our DNS queries would leak out around the tunnel.
                // Instead we have to bounce things through the objective C trampoline code (which
                // is what actually handles the upstream querying) so that it can call into Apple's
                // special snowflake API to set up a socket that has the magic Apple snowflake sauce
                // added on top so that it actually routes through the tunnel instead of around it.
                //
                // But the trampoline *always* tries to send the packet through the tunnel, and that
                // will only work in exit mode.
                //
                // All of this macos behaviour is all carefully and explicitly documented by Apple
                // with plenty of examples and other exposition, of course, just like all of their
                // wonderful new APIs to reinvent standard unix interfaces with half-baked
                // replacements.

                if constexpr (platform::is_apple)
                {
                    if (dns.host() == "127.0.0.1" and dns.port() == apple::dns_trampoline_port)
                    {
                        // macOS is stupid: the default (0.0.0.0) fails with "send failed: Can't
                        // assign requested address" when unbound tries to connect to the localhost
                        // address using a source address of 0.0.0.0.  Yay apple.
                        set_opt("outgoing-interface:", "127.0.0.1");

                        // The trampoline expects just a single source port (and sends everything
                        // back to it).
                        set_opt("outgoing-range:", "1");
                        set_opt("outgoing-port-avoid:", "0-65535");
                        set_opt("outgoing-port-permit:", "{}", apple::dns_trampoline_source_port);
                        return true;
                    }
                }
                return false;
            }

            void configure_upstream(const llarp::DnsConfig& conf)
            {
                bool is_apple_tramp = false;

                // set up forward dns
                for (const auto& dns : conf._upstream_dns)
                {
                    add_upstream_resolver(dns);
                    is_apple_tramp = is_apple_tramp or configure_apple_trampoline(dns);
                }

                if (auto maybe_addr = conf._query_bind; maybe_addr and not is_apple_tramp)
                {
                    oxen::quic::Address addr{*maybe_addr};
                    auto host = addr.host();

                    if (addr.port() == 0)
                    {
                        // unbound manages their own sockets because of COURSE it does. so we find
                        // an open port on our system and use it so we KNOW what it is before giving
                        // it to unbound to explicitly bind to JUST that port.

                        auto fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
                        if (fd == INVALID_SOCKET)
#else
                        if (fd == -1)
#endif
                        {
                            throw std::invalid_argument{
                                fmt::format("Failed to create UDP socket for unbound: {}", strerror(errno))};
                        }

#ifdef _WIN32
#define CLOSE closesocket
#else
#define CLOSE close
#endif
                        if (0 != bind(fd, static_cast<const sockaddr*>(addr), addr.socklen()))
                        {
                            CLOSE(fd);
                            throw std::invalid_argument{
                                fmt::format("Failed to bind UDP socket for unbound: {}", strerror(errno))};
                        }
                        struct sockaddr_storage sas;
                        auto* sa = reinterpret_cast<struct sockaddr*>(&sas);
                        socklen_t sa_len = sizeof(sas);
                        int rc = getsockname(fd, sa, &sa_len);
                        CLOSE(fd);
#undef CLOSE
                        if (rc != 0)
                        {
                            throw std::invalid_argument{
                                fmt::format("Failed to query UDP port for unbound: {}", strerror(errno))};
                        }

                        addr = oxen::quic::Address{sa, sizeof(sockaddr)};
                    }
                    _local_addr = addr;

                    log::info(logcat, "sending dns queries from {}", addr.to_string());
                    // set up query bind port if needed
                    set_opt("outgoing-interface:", host);
                    set_opt("outgoing-range:", "1");
                    set_opt("outgoing-port-avoid:", "0-65535");
                    set_opt("outgoing-port-permit:", "{}", addr.port());
                }
            }

            void set_opt(const std::string& key, const std::string& val)
            {
                ub_ctx_set_option(m_ctx, key.c_str(), val.c_str());
            }

            // Wrapper around the above that takes 3+ arguments: the 2nd arg gets formatted with the
            // remaining args, and the formatted string passed to the above as `val`.
            template <typename... FmtArgs, std::enable_if_t<sizeof...(FmtArgs), int> = 0>
            void set_opt(const std::string& key, std::string_view format, FmtArgs&&... args)
            {
                set_opt(key, fmt::format(format, std::forward<FmtArgs>(args)...));
            }

            // Copy of the DNS config (a copy because on some platforms, like Apple, we change the
            // applied upstream DNS settings when turning on/off exit mode).
            llarp::DnsConfig m_conf;

           public:
            explicit Resolver(const std::shared_ptr<EvLoop_deprecated>& loop, llarp::DnsConfig conf)
                : _loop{loop}, m_conf{std::move(conf)}
            {
                up(m_conf);
            }

            ~Resolver() override
            {
                down();
            }

            std::string_view resolver_name() const override
            {
                return "unbound";
            }

            std::optional<oxen::quic::Address> get_local_addr() const override
            {
                return _local_addr;
            }

            void remove_pending(const std::shared_ptr<Query>& query)
            {
                _pending.erase(query);
            }

            void up(const llarp::DnsConfig& conf)
            {
                if (m_ctx)
                    throw std::logic_error{"Internal error: attempt to Up() dns server multiple times"};

                m_ctx = ::ub_ctx_create();
                // set libunbound settings

                set_opt("do-tcp:", "no");

                for (const auto& [k, v] : conf.extra_opts)
                    set_opt(k, v);

                // add host files
                for (const auto& file : conf.hostfiles)
                {
                    const auto str = file.u8string();
                    if (auto ret = ub_ctx_hosts(m_ctx, str.c_str()))
                    {
                        throw std::runtime_error{fmt::format("Failed to add host file {}: {}", file, ub_strerror(ret))};
                    }
                }

                configure_upstream(conf);

                // set async
                ub_ctx_async(m_ctx, 1);
                // setup mainloop
#ifdef _WIN32
                running = true;
                runner = std::thread{[this]() {
                    while (running)
                    {
                        // poll and process callbacks it this thread
                        if (ub_poll(m_ctx))
                        {
                            ub_process(m_ctx);
                        }
                        else  // nothing to do, sleep.
                            std::this_thread::sleep_for(10ms);
                    }
                }};
#else
                if (auto loop = _loop.lock())
                {
                    if (auto loop_ptr = loop->MaybeGetUVWLoop())
                    {
                        _poller = loop_ptr->resource<uvw::PollHandle>(ub_fd(m_ctx));
                        _poller->on<uvw::PollEvent>([this](auto&, auto&) { ub_process(m_ctx); });
                        _poller->start(uvw::PollHandle::Event::READABLE);
                        return;
                    }
                }
                throw std::runtime_error{"no uvw loop"};
#endif
            }

            void down() override
            {
#ifdef _WIN32
                if (running.exchange(false))
                {
                    log::debug(logcat, "shutting down win32 dns thread");
                    runner.join();
                }
#else
                if (_poller)
                    _poller->close();
#endif
                if (m_ctx)
                {
                    ::ub_ctx_delete(m_ctx);
                    m_ctx = nullptr;

                    // destroy any outstanding queries that unbound hasn't fired yet
                    if (not _pending.empty())
                    {
                        log::debug(logcat, "cancelling {} pending queries", _pending.size());
                        // We must copy because Cancel does a loop call to remove itself, but since
                        // we are already in the main loop it happens immediately, which would
                        // invalidate our iterator if we were looping through m_Pending at the time.
                        auto copy = _pending;
                        for (const auto& query : copy)
                            query->cancel();
                    }
                }
            }

            int rank() const override
            {
                return 10;
            }

            void reset_resolver(std::optional<std::vector<oxen::quic::Address>> replace_upstream) override
            {
                down();
                if (replace_upstream)
                    m_conf._upstream_dns = std::move(*replace_upstream);
                up(m_conf);
            }

            template <typename Callable>
            void call(Callable&& f)
            {
                if (auto loop = _loop.lock())
                    loop->call(std::forward<Callable>(f));
                else
                    log::critical(logcat, "no mainloop?");
            }

            bool maybe_hook_dns(
                std::shared_ptr<PacketSource_Base> source,
                const Message& query,
                const SockAddr_deprecated& to,
                const SockAddr_deprecated& from) override
            {
                auto tmp = std::make_shared<Query>(weak_from_this(), query, source, to, from);
                // no questions, send fail
                if (query.questions.empty())
                {
                    log::info(logcat, "dns from {} to {} has empty query questions, sending failure reply", from, to);
                    tmp->cancel();
                    return true;
                }

                for (const auto& q : query.questions)
                {
                    // dont process .loki or .snode
                    if (q.HasTLD(".loki") or q.HasTLD(".snode"))
                    {
                        log::warning(
                            logcat,
                            "dns from {} to {} is for .loki or .snode but got to the unbound "
                            "resolver, sending "
                            "failure reply",
                            from,
                            to);
                        tmp->cancel();
                        return true;
                    }
                }
                if (not m_ctx)
                {
                    // we are down
                    log::debug(
                        logcat,
                        "dns from {} to {} got to the unbound resolver, but the resolver isn't set "
                        "up, "
                        "sending failure reply",
                        from,
                        to);
                    tmp->cancel();
                    return true;
                }

#ifdef _WIN32
                if (not running)
                {
                    // we are stopping the win32 thread
                    log::debug(
                        logcat,
                        "dns from {} to {} got to the unbound resolver, but the resolver isn't "
                        "running, "
                        "sending failure reply",
                        from,
                        to);
                    tmp->Cancel();
                    return true;
                }
#endif
                const auto& q = query.questions[0];
                if (auto err = ub_resolve_async(
                        m_ctx, q.Name().c_str(), q.qtype, q.qclass, tmp.get(), &Resolver::callback, nullptr))
                {
                    log::warning(logcat, "failed to send upstream query with libunbound: {}", ub_strerror(err));
                    tmp->cancel();
                }
                else
                {
                    log::trace(logcat, "dns from {} to {} processing via libunbound", from, to);
                    _pending.insert(std::move(tmp));
                }

                return true;
            }
        };

        void Query::send_reply(llarp::OwnedBuffer replyBuf)
        {
            if (_done.test_and_set())
                return;
            auto parent_ptr = parent.lock();
            if (parent_ptr)
            {
                parent_ptr->call(
                    [self = shared_from_this(), parent_ptr = std::move(parent_ptr), buf = replyBuf.copy()] {
                        log::trace(
                            logcat,
                            "forwarding dns response from libunbound to userland (resolverAddr: {}, "
                            "askerAddr: {})",
                            self->resolverAddr,
                            self->askerAddr);
                        self->src->send_to(self->askerAddr, self->resolverAddr, OwnedBuffer::copy_from(buf));
                        // remove query
                        parent_ptr->remove_pending(self);
                    });
            }
            else
                log::error(logcat, "no parent");
        }
    }  // namespace libunbound

    Server::Server(std::shared_ptr<EvLoop_deprecated> loop, llarp::DnsConfig conf, unsigned int netif)
        : _loop{std::move(loop)}, _conf{std::move(conf)}, _platform{create_platform()}, m_NetIfIndex{std::move(netif)}
    {}

    std::vector<std::weak_ptr<Resolver_Base>> Server::get_all_resolvers() const
    {
        return {_resolvers.begin(), _resolvers.end()};
    }

    void Server::start()
    {
        // set up udp sockets
        for (const auto& addr : _conf._bind_addrs)
        {
            if (auto ptr = make_packet_source_on(addr, _conf))
                add_packet_source(std::move(ptr));
        }

        // add default resolver as needed
        if (auto ptr = make_default_resolver())
            add_resolver(ptr);
    }

    std::shared_ptr<I_Platform> Server::create_platform() const
    {
        auto plat = std::make_shared<Multi_Platform>();
        if constexpr (llarp::platform::has_systemd)
        {
            plat->add_impl(std::make_unique<SD_Platform_t>());
            plat->add_impl(std::make_unique<NM_Platform_t>());
        }
        return plat;
    }

    std::shared_ptr<PacketSource_Base> Server::make_packet_source_on(
        const oxen::quic::Address& addr, const llarp::DnsConfig&)
    {
        return std::make_shared<UDPReader>(*this, _loop, addr);
    }

    std::shared_ptr<Resolver_Base> Server::make_default_resolver()
    {
        if (_conf._upstream_dns.empty())
        {
            log::info(
                logcat,
                "explicitly no upstream dns providers specified, we will not resolve anything but "
                ".loki "
                "and .snode");
            return nullptr;
        }

        return std::make_shared<libunbound::Resolver>(_loop, _conf);
    }

    std::vector<SockAddr_deprecated> Server::bound_packet_source_addrs() const
    {
        std::vector<SockAddr_deprecated> addrs;
        for (const auto& src : _packet_sources)
        {
            if (auto ptr = src.lock())
                if (auto maybe_addr = ptr->bound_on())
                    addrs.emplace_back(*maybe_addr);
        }
        return addrs;
    }

    std::optional<SockAddr_deprecated> Server::first_bound_packet_source_addr() const
    {
        for (const auto& src : _packet_sources)
        {
            if (auto ptr = src.lock())
                if (auto bound = ptr->bound_on())
                    return bound;
        }
        return std::nullopt;
    }

    void Server::add_resolver(std::weak_ptr<Resolver_Base> resolver)
    {
        _resolvers.insert(resolver);
    }

    void Server::add_resolver(std::shared_ptr<Resolver_Base> resolver)
    {
        _owned_resolvers.insert(resolver);
        add_resolver(std::weak_ptr<Resolver_Base>{resolver});
    }

    void Server::add_packet_source(std::weak_ptr<PacketSource_Base> pkt)
    {
        _packet_sources.push_back(pkt);
    }

    void Server::add_packet_source(std::shared_ptr<PacketSource_Base> pkt)
    {
        add_packet_source(std::weak_ptr<PacketSource_Base>{pkt});
        _owned_packet_sources.push_back(std::move(pkt));
    }

    void Server::stop()
    {
        for (const auto& resolver : _resolvers)
        {
            if (auto ptr = resolver.lock())
                ptr->down();
        }
    }

    void Server::reset()
    {
        for (const auto& resolver : _resolvers)
        {
            if (auto ptr = resolver.lock())
                ptr->reset_resolver();
        }
    }

    void Server::set_dns_mode(bool all_queries)
    {
        if (auto maybe_addr = first_bound_packet_source_addr())
            _platform->set_resolver(m_NetIfIndex, *maybe_addr, all_queries);
    }

    bool Server::maybe_handle_packet(
        std::shared_ptr<PacketSource_Base> ptr,
        const oxen::quic::Address& to,
        const oxen::quic::Address& from,
        llarp::OwnedBuffer buf)
    {
        // dont process to prevent feedback loop
        if (ptr->would_loop(to, from))
        {
            log::warning(logcat, "preventing dns packet replay to={} from={}", to, from);
            return false;
        }

        auto maybe = maybe_parse_dns_msg(buf);
        if (not maybe)
        {
            log::warning(logcat, "invalid dns message format from {} to dns listener on {}", from, to);
            return false;
        }

        auto& msg = *maybe;
        // we don't provide a DoH resolver because it requires verified TLS
        // TLS needs X509/ASN.1-DER and opting into the Root CA Cabal
        // thankfully mozilla added a backdoor that allows ISPs to turn it off
        // so we disable DoH for firefox using mozilla's ISP backdoor
        // see: https://github.com/oxen-io/lokinet/issues/832
        for (const auto& q : msg.questions)
        {
            // is this firefox looking for their backdoor record?
            if (q.IsName("use-application-dns.net"))
            {
                // yea it is, let's turn off DoH because god is dead.
                msg.add_nx_reply();
                // press F to pay respects and send it back where it came from
                ptr->send_to(from, to, msg.to_buffer());
                return true;
            }
        }

        for (const auto& resolver : _resolvers)
        {
            if (auto res_ptr = resolver.lock())
            {
                log::trace(logcat, "check resolver {} for dns from {} to {}", res_ptr->resolver_name(), from, to);
                if (res_ptr->maybe_hook_dns(ptr, msg, to, from))
                {
                    log::trace(logcat, "resolver {} handling dns from {} to {}", res_ptr->resolver_name(), from, to);
                    return true;
                }
            }
        }
        return false;
    }

}  // namespace llarp::dns
