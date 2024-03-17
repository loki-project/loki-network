#pragma once

#include "common.hpp"

#include <llarp/path/path_types.hpp>
#include <llarp/router_id.hpp>

#include <vector>

namespace llarp
{
    namespace link
    {
        struct Connection;
    }

    struct Router;

    /// parsed link layer message
    struct AbstractLinkMessage : private AbstractSerializable
    {
        std::shared_ptr<link::Connection> conn;
        HopID pathid;

        uint64_t version = llarp::constants::proto_version;

        AbstractLinkMessage() = default;

        virtual ~AbstractLinkMessage() = default;

        std::string bt_encode() const override = 0;

        virtual bool handle_message(Router* router) const = 0;

        virtual void clear() = 0;

        // the name of this kind of message
        virtual const char* name() const = 0;

        /// get message prority, higher value means more important
        virtual uint16_t priority() const
        {
            return 1;
        }

        // methods we do not want to inherit onwards from AbstractSerializable
        void bt_encode(oxenc::bt_dict_producer&) const final
        {
            throw std::runtime_error{"Error: Link messages should not encode directly to a bt list producer!"};
        }
    };
}  // namespace llarp
