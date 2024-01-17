#pragma once

#include "path_types.hpp"

#include <llarp/crypto/types.hpp>
#include <llarp/util/decaying_hashset.hpp>
#include <llarp/util/types.hpp>

#include <memory>
#include <vector>

struct llarp_buffer_t;

namespace llarp
{
    struct Router;

    namespace routing
    {
        struct AbstractRoutingMessage;
    }

    namespace path
    {
        std::string make_onion_payload(
            const SymmNonce& nonce, const HopID& path_id, const std::string_view& inner_payload);
        std::string make_onion_payload(const SymmNonce& nonce, const HopID& path_id, const ustring_view& inner_payload);

        struct AbstractHopHandler
        {
            virtual ~AbstractHopHandler() = default;

            virtual HopID RXID() const = 0;

            virtual bool is_expired(llarp_time_t now) const = 0;

            virtual bool ExpiresSoon(llarp_time_t now, llarp_time_t dlt) const = 0;

            /// sends a control request along a path
            ///
            /// performs the necessary onion encryption before sending.
            /// func will be called when a timeout occurs or a response is received.
            /// if a response is received, onion decryption is performed before func is called.
            ///
            /// func is called with a bt-encoded response string (if applicable), and
            /// a timeout flag (if set, response string will be empty)
            virtual bool send_path_control_message(
                std::string method, std::string body, std::function<void(std::string)> func) = 0;

            virtual bool send_path_data_message(std::string body) = 0;

            /// return timestamp last remote activity happened at
            virtual llarp_time_t LastRemoteActivityAt() const = 0;
        };

        // using HopHandler_ptr = std::shared_ptr<AbstractHopHandler>;
    }  // namespace path
}  // namespace llarp
