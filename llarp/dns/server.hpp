#pragma once

#include "message.hpp"
#include <llarp/config/config.hpp>
#include <llarp/ev/ev.hpp>
#include <llarp/net/net.hpp>
#include <llarp/util/fs.hpp>
#include <set>

namespace llarp::dns
{
  /// a job handling 1 dns query
  class QueryJob_Base
  {
   protected:
    /// the original dns query
    Message m_Query;

   public:
    explicit QueryJob_Base(Message query) : m_Query{std::move(query)}
    {}

    virtual ~QueryJob_Base() = default;

    Message&
    Underlying()
    {
      return m_Query;
    }

    const Message&
    Underlying() const
    {
      return m_Query;
    }

    /// cancel this operation and inform anyone who cares
    void
    Cancel() const;

    /// send a raw buffer back to the querier
    virtual void
    SendReply(llarp::OwnedBuffer replyBuf) const = 0;
  };

  class PacketSource_Base
  {
   public:
    virtual ~PacketSource_Base() = default;

    /// return true if traffic with source and dest addresses would cause a
    /// loop in resolution and thus should not be sent to query handlers
    virtual bool
    WouldLoop(const SockAddr& to, const SockAddr& from) const = 0;

    /// send packet with src and dst address containing buf on this packet source
    virtual void
    SendTo(const SockAddr& to, const SockAddr& from, OwnedBuffer buf) const = 0;

    /// stop reading packets and end operation
    virtual void
    Stop() = 0;

    /// returns the sockaddr we are bound on if applicable
    virtual std::optional<SockAddr>
    BoundOn() const = 0;
  };

  /// non complex implementation of QueryJob_Base for use in things that
  /// only ever called on the mainloop thread
  class QueryJob : public QueryJob_Base, std::enable_shared_from_this<QueryJob>
  {
    std::weak_ptr<PacketSource_Base> src;
    const SockAddr resolver;
    const SockAddr asker;

   public:
    explicit QueryJob(
        std::weak_ptr<PacketSource_Base> source,
        const Message& query,
        const SockAddr& to_,
        const SockAddr& from_)
        : QueryJob_Base{query}, src{source}, resolver{to_}, asker{from_}
    {}

    void
    SendReply(llarp::OwnedBuffer replyBuf) const override
    {
      if (auto ptr = src.lock())
        ptr->SendTo(asker, resolver, std::move(replyBuf));
    }
  };

  /// handler of dns query hooking
  /// intercepts dns for internal processing
  class Resolver_Base
  {
   protected:
    /// return the sorting order for this resolver
    /// lower means it will be tried first
    virtual int
    Rank() const = 0;

   public:
    virtual ~Resolver_Base() = default;

    /// less than via rank
    bool
    operator<(const Resolver_Base& other) const
    {
      return Rank() < other.Rank();
    }

    /// greater than via rank
    bool
    operator>(const Resolver_Base& other) const
    {
      return Rank() > other.Rank();
    }

    /// get printable name
    virtual std::string_view
    ResolverName() const = 0;

    /// reset state
    virtual void
    ResetInternalState(){};

    /// cancel all pending requests and ceace further operation
    virtual void
    CancelPendingQueries(){};
    /// attempt to handle a dns message
    /// returns true if we consumed this query and it should not be processed again
    virtual bool
    MaybeHookDNS(
        std::weak_ptr<PacketSource_Base> source,
        const Message& query,
        const SockAddr& to,
        const SockAddr& from) = 0;

    /// Returns true if a packet with to and from addresses is something that would cause a
    /// resolution loop and thus should not be used on this resolver
    virtual bool
    WouldLoop(const SockAddr& to, const SockAddr& from) const
    {
      (void)to;
      (void)from;
      return false;
    };
  };

  // Base class for DNS proxy
  class Server : public std::enable_shared_from_this<Server>
  {
   protected:
    /// add a packet source to this server, does share ownership
    void
    AddPacketSource(std::shared_ptr<PacketSource_Base> resolver);
    /// add a resolver to this packet handler, does share ownership
    void
    AddResolver(std::shared_ptr<Resolver_Base> resolver);

   public:
    virtual ~Server() = default;
    explicit Server(EventLoop_ptr loop, llarp::DnsConfig conf);

    /// returns all sockaddr we have from all of our PacketSources
    std::vector<SockAddr>
    BoundPacketSourceAddrs() const;

    /// returns the first sockaddr we have on our packet sources if we have one
    std::optional<SockAddr>
    FirstBoundPacketSourceAddr() const;

    /// add a resolver to this packet handler, does not share ownership
    void
    AddResolver(std::weak_ptr<Resolver_Base> resolver);

    /// add a packet source to this server, does not share ownership
    void
    AddPacketSource(std::weak_ptr<PacketSource_Base> resolver);

    /// create a packet source bound on bindaddr but does not add it
    virtual std::shared_ptr<PacketSource_Base>
    MakePacketSourceOn(const SockAddr& bindaddr, const llarp::DnsConfig& conf);

    /// sets up all internal binds and such and begins operation
    virtual void
    Start();

    /// stops all operation
    virtual void
    Stop();

    /// reset the internal state
    virtual void
    Reset();

    /// create the default resolver for out config
    virtual std::shared_ptr<Resolver_Base>
    MakeDefaultResolver();

    /// feed a packet buffer from a packet source
    /// returns true if we decided to process the packet and consumed it
    /// returns false if we dont want to process the packet
    bool
    MaybeHandlePacket(
        std::weak_ptr<PacketSource_Base> pktsource,
        const SockAddr& resolver,
        const SockAddr& from,
        llarp::OwnedBuffer buf);

   protected:
    EventLoop_ptr m_Loop;
    llarp::DnsConfig m_Config;

   private:
    std::set<std::shared_ptr<Resolver_Base>, ComparePtr<std::shared_ptr<Resolver_Base>>>
        m_OwnedResolvers;
    std::set<std::weak_ptr<Resolver_Base>, CompareWeakPtr<Resolver_Base>> m_Resolvers;

    std::vector<std::weak_ptr<PacketSource_Base>> m_PacketSources;
    std::vector<std::shared_ptr<PacketSource_Base>> m_OwnedPacketSources;
  };

}  // namespace llarp::dns
