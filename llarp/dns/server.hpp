#pragma once

#include "message.hpp"
#include "platform.hpp"

#include <llarp/config/config.hpp>
#include <llarp/ev/loop.hpp>
#include <llarp/net/ip_packet.hpp>
#include <llarp/util/compare_ptr.hpp>

#include <oxen/quic.hpp>

#include <set>
#include <utility>

namespace llarp::dns
{
    /// a job handling 1 dns query
    class QueryJob_Base
    {
      protected:
        /// the original dns query
        Message _query;

        /// True if we've sent a reply (including via a call to cancel)
        std::atomic_flag _done = ATOMIC_FLAG_INIT;

      public:
        explicit QueryJob_Base(Message query) : _query{std::move(query)} {}

        virtual ~QueryJob_Base() = default;

        Message& underlying() { return _query; }

        const Message& underlying() const { return _query; }

        /// cancel this operation and inform anyone who cares
        void cancel();

        /// send a raw buffer back to the querier
        virtual void send_reply(std::vector<uint8_t> buf) = 0;
    };

    class PacketSource_Base
    {
      public:
        virtual ~PacketSource_Base() = default;

        /// return true if traffic with source and dest addresses would cause a
        /// loop in resolution and thus should not be sent to query handlers
        virtual bool would_loop(const oxen::quic::Address& to, const oxen::quic::Address& from) const = 0;

        /// send packet with src and dst address containing buf on this packet source
        /// two overrides, lets see which is more useful and drop ze ozzzerrrr
        virtual void send_to(const oxen::quic::Address& to, const oxen::quic::Address& from, IPPacket data) const = 0;
        virtual void send_to(
            const oxen::quic::Address& to, const oxen::quic::Address& from, std::vector<uint8_t> data) const
        {
            send_to(to, from, IPPacket{std::move(data)});
        }

        /// stop reading packets and end operation
        virtual void stop() = 0;

        /// returns the sockaddr we are bound on if applicable
        virtual std::optional<oxen::quic::Address> bound_on() const = 0;
    };

    /// a packet source which will override the sendto function of an wrapped packet source to
    /// construct a raw ip packet as a reply
    class PacketSource_Wrapper : public PacketSource_Base
    {
        std::weak_ptr<PacketSource_Base> _wrapped;
        ip_pkt_hook _write_pkt;

      public:
        explicit PacketSource_Wrapper(std::weak_ptr<PacketSource_Base> wrapped, ip_pkt_hook write_packet)
            : _wrapped{std::move(wrapped)}, _write_pkt{std::move(write_packet)}
        {}

        bool would_loop(const oxen::quic::Address& to, const oxen::quic::Address& from) const override
        {
            if (auto ptr = _wrapped.lock())
                return ptr->would_loop(to, from);

            return true;
        }

        void send_to(const oxen::quic::Address& to, const oxen::quic::Address& from, IPPacket data) const override
        {
            // TOFIX: this
            (void)to;
            (void)from;
            (void)data;
            _write_pkt(data);
        }

        void send_to(
            const oxen::quic::Address& to, const oxen::quic::Address& from, std::vector<uint8_t> data) const override
        {
            send_to(to, from, IPPacket{std::move(data)});
        }

        /// stop reading packets and end operation
        void stop() override
        {
            if (auto ptr = _wrapped.lock())
                ptr->stop();
        }

        /// returns the sockaddr we are bound on if applicable
        std::optional<oxen::quic::Address> bound_on() const override
        {
            if (auto ptr = _wrapped.lock())
                return ptr->bound_on();

            return std::nullopt;
        }
    };

    /// non complex implementation of QueryJob_Base for use in things that
    /// only ever called on the mainloop thread
    class QueryJob : public QueryJob_Base, std::enable_shared_from_this<QueryJob>
    {
        std::shared_ptr<PacketSource_Base> src;
        const oxen::quic::Address resolver;
        const oxen::quic::Address asker;

      public:
        explicit QueryJob(
            std::shared_ptr<PacketSource_Base> source,
            const Message& query,
            const oxen::quic::Address& to_,
            const oxen::quic::Address& from_)
            : QueryJob_Base{query}, src{std::move(source)}, resolver{to_}, asker{from_}
        {}

        void send_reply(std::vector<uint8_t> buf) override { src->send_to(asker, resolver, IPPacket{std::move(buf)}); }
    };

    /// handler of dns query hooking
    /// intercepts dns for internal processing
    class Resolver_Base
    {
      protected:
        /// return the sorting order for this resolver
        /// lower means it will be tried first
        virtual int rank() const = 0;

      public:
        virtual ~Resolver_Base() = default;

        /// less than via rank
        bool operator<(const Resolver_Base& other) const { return rank() < other.rank(); }

        /// greater than via rank
        bool operator>(const Resolver_Base& other) const { return rank() > other.rank(); }

        /// get local socket address that queries are sent from
        virtual std::optional<oxen::quic::Address> get_local_addr() const { return std::nullopt; }

        /// get printable name
        virtual std::string_view resolver_name() const = 0;

        /// reset the resolver state, optionally replace upstream info with new info.  The default
        /// base implementation does nothing.
        virtual void reset_resolver(std::optional<std::vector<oxen::quic::Address>> = std::nullopt) {}

        /// cancel all pending requests and cease further operation.  Default operation is a no-op.
        virtual void down() {}

        /// attempt to handle a dns message
        /// returns true if we consumed this query and it should not be processed again
        virtual bool maybe_hook_dns(
            std::shared_ptr<PacketSource_Base> source,
            const Message& query,
            const oxen::quic::Address& to,
            const oxen::quic::Address& from) = 0;
    };

    // Base class for DNS proxy
    class Server : public std::enable_shared_from_this<Server>
    {
      protected:
        /// add a packet source to this server, does share ownership
        void add_packet_source(std::shared_ptr<PacketSource_Base> resolver);
        /// add a resolver to this packet handler, does share ownership
        void add_resolver(std::shared_ptr<Resolver_Base> resolver);

        /// create the platform dependant dns stuff
        virtual std::shared_ptr<I_Platform> create_platform() const;

      public:
        virtual ~Server() = default;

        explicit Server(std::shared_ptr<EventLoop> loop, llarp::DnsConfig conf, unsigned int netif_index);

        /// returns all sockaddr we have from all of our PacketSources
        std::vector<oxen::quic::Address> bound_packet_source_addrs() const;

        /// returns the first sockaddr we have on our packet sources if we have one
        std::optional<oxen::quic::Address> first_bound_packet_source_addr() const;

        /// add a resolver to this packet handler, does not share ownership
        void add_resolver(std::weak_ptr<Resolver_Base> resolver);

        /// add a packet source to this server, does not share ownership
        void add_packet_source(std::weak_ptr<PacketSource_Base> resolver);

        /// create a packet source bound on bindaddr but does not add it
        virtual std::shared_ptr<PacketSource_Base> make_packet_source_on(
            const oxen::quic::Address& bindaddr, const llarp::DnsConfig& conf);

        /// sets up all internal binds and such and begins operation
        virtual void start();

        /// stops all operation
        virtual void stop();

        /// reset the internal state
        virtual void reset();

        /// create the default resolver for out config
        virtual std::shared_ptr<Resolver_Base> make_default_resolver();

        std::vector<std::weak_ptr<Resolver_Base>> get_all_resolvers() const;

        /// feed a packet buffer from a packet source.
        /// returns true if we decided to process the packet and consumed it
        /// returns false if we dont want to process the packet
        bool maybe_handle_packet(
            std::shared_ptr<PacketSource_Base> pktsource,
            const oxen::quic::Address& resolver,
            const oxen::quic::Address& from,
            IPPacket buf);

        /// set which dns mode we are in.
        /// true for intercepting all queries. false for just .loki and .snode
        void set_dns_mode(bool all_queries);

      protected:
        std::shared_ptr<EventLoop> _loop;
        llarp::DnsConfig _conf;
        std::shared_ptr<I_Platform> _platform;

      private:
        const unsigned int m_NetIfIndex;
        std::set<std::shared_ptr<Resolver_Base>, ComparePtr<std::shared_ptr<Resolver_Base>>> _owned_resolvers;
        std::set<std::weak_ptr<Resolver_Base>, CompareWeakPtr<Resolver_Base>> _resolvers;

        std::vector<std::shared_ptr<PacketSource_Base>> _owned_packet_sources;
        std::vector<std::weak_ptr<PacketSource_Base>> _packet_sources;
    };

}  // namespace llarp::dns
