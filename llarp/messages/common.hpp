#pragma once

#include <llarp/contact/router_id.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dht/key.hpp>
#include <llarp/path/path_types.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>

#include <oxenc/bt.h>

namespace llarp
{
    namespace messages
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
    }  // namespace messages

    namespace Onion
    {
        static auto logcat = llarp::log::Cat("onion");

        /** Bt-encoded contents:
            - 'h' : HopID of the next layer of the onion
            - 'n' : Symmetric nonce used to encrypt the layer
            - 'x' : Encrypted payload transmitted to next recipient
        */
        inline static std::string serialize(
            const SymmNonce& nonce, const HopID& hop_id, const std::string_view& payload)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("h", hop_id.to_view());
            btdp.append("n", nonce.to_view());
            btdp.append("x", payload);

            return std::move(btdp).str();
        }

        inline static std::string serialize(const SymmNonce& nonce, const HopID& hop_id, const ustring_view& payload)
        {
            return serialize(
                nonce, hop_id, std::string_view{reinterpret_cast<const char*>(payload.data()), payload.size()});
        }

        inline static std::tuple<ustring, ustring, ustring> deserialize(oxenc::bt_dict_consumer& btdc)
        {
            ustring hopid, nonce, payload;

            try
            {
                hopid = btdc.require<ustring>("h");
                nonce = btdc.require<ustring>("n");
                payload = btdc.require<ustring>("x");
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing onion data:{}", e.what());
                throw;
            }

            return {std::move(hopid), std::move(nonce), std::move(payload)};
        }
    }  //  namespace Onion

}  // namespace llarp
