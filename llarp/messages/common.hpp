#pragma once

#include <llarp/crypto/crypto.hpp>
#include <llarp/dht/key.hpp>
#include <llarp/path/path_types.hpp>
#include <llarp/router_id.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>

#include <oxenc/bt.h>

namespace llarp
{
    namespace messages
    {
        inline std::string serialize_response(oxenc::bt_dict supplement = {})
        {
            return oxenc::bt_serialize(supplement);
        }

        // ideally STATUS is the first key in a bt-dict, so use a single, early ascii char
        inline const auto STATUS_KEY = "!"s;
        inline const auto TIMEOUT_RESPONSE = serialize_response({{STATUS_KEY, "TIMEOUT"}});
        inline const auto ERROR_RESPONSE = serialize_response({{STATUS_KEY, "ERROR"}});
        inline const auto OK_RESPONSE = serialize_response({{STATUS_KEY, "OK"}});
    }  // namespace messages

    /// abstract base class for serialized messages
    struct AbstractSerializable
    {
        virtual std::string bt_encode() const = 0;
        virtual void bt_encode(oxenc::bt_dict_producer& btdp) const = 0;
    };

    struct AbstractMessageHandler
    {
        virtual bool handle_message(AbstractSerializable&) = 0;
    };
}  // namespace llarp
