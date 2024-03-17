#pragma once

#include <llarp/address/types.hpp>
#include <llarp/util/logging.hpp>

#include <oxen/quic.hpp>

#include <memory>
#include <stdexcept>
#include <string>

#ifndef _WIN32
#include <net/if.h>
#endif

namespace llarp::dns
{
    /// sets dns settings in a platform dependant way
    class I_Platform
    {
      public:
        virtual ~I_Platform() = default;

        /// Attempts to set lokinet as the DNS server.
        /// throws if unsupported or fails.
        ///
        ///
        /// \param if_index -- the interface index to which we add the DNS servers, this can be
        /// gotten from the interface name e.g. lokitun0 (Typically tun_endpoint.GetIfName().) and
        /// then put through if_nametoindex(). \param dns -- the listening address of the lokinet
        /// DNS server \param global -- whether to set up lokinet for all DNS queries (true) or just
        /// .loki & .snode addresses (false).
        virtual void set_resolver(unsigned int if_index, oxen::quic::Address dns, bool global) = 0;
    };

    /// a dns platform does silently does nothing, successfully
    class Null_Platform : public I_Platform
    {
      public:
        ~Null_Platform() override = default;
        void set_resolver(unsigned int, oxen::quic::Address, bool) override
        {}
    };

    /// a collection of dns platforms that are tried in order when setting dns
    class Multi_Platform : public I_Platform
    {
        std::vector<std::unique_ptr<I_Platform>> m_Impls;

      public:
        ~Multi_Platform() override = default;
        /// add a platform to be owned
        void add_impl(std::unique_ptr<I_Platform> impl);

        /// try all owned platforms to set the resolver, throws if none of them work
        void set_resolver(unsigned int if_index, oxen::quic::Address dns, bool global) override;
    };
}  // namespace llarp::dns
