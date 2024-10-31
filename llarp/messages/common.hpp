#pragma once

#include <llarp/contact/router_id.hpp>
#include <llarp/contact/tag.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dht/key.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>

#include <oxenc/bt.h>

namespace llarp::messages
{
    static auto logcat = log::Cat("messages");

    inline std::string serialize_response(oxenc::bt_dict supplement = {})
    {
        return oxenc::bt_serialize(supplement);
    }

    // ideally STATUS is the first key in a bt-dict, so use a single, early ascii char
    inline const auto STATUS_KEY = "!"s;
    inline const auto TIMEOUT_RESPONSE = serialize_response({{STATUS_KEY, "TIMEOUT"}});
    inline const auto ERROR_RESPONSE = serialize_response({{STATUS_KEY, "ERROR"}});
    inline const auto OK_RESPONSE = serialize_response({{STATUS_KEY, "OK"}});
}  // namespace llarp::messages
