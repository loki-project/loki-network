#pragma once

#include "json_binary_proxy.hpp"
#include "json_bt.hpp"

#include <llarp/config/config.hpp>

#include <nlohmann/json_fwd.hpp>
#include <oxen/log/omq_logger.hpp>
#include <oxenmq/address.h>
#include <oxenmq/oxenmq.h>

#include <string_view>

namespace tools
{
    //  Type wrapper that contains an arbitrary list of types.
    template <typename...>
    struct type_list
    {};
}  // namespace tools

namespace llarp::rpc
{
    //  Base class that all RPC requests will expand for each endpoint type
    struct RPCRequest
    {
      private:
        bool bt = false;

      public:
        //  Returns true if response is bt-encoded, and false for json
        //  Note: do not set value
        bool is_bt() const { return bt; }

        //  Callable method to indicate request is bt-encoded
        void set_bt()
        {
            bt = true;
            response_b64.format = llarp::rpc::json_binary_proxy::fmt::bt;
            response_hex.format = llarp::rpc::json_binary_proxy::fmt::bt;
        }

        //  Invoked if this.replier is still present. If it is "stolen" by endpoint (moved from
        //  RPC struct), then endpoint handles sending reply
        void send_response()
        {
            replier->reply(is_bt() ? oxenc::bt_serialize(json_to_bt(std::move(response))) : response.dump());
        }

        void send_response(nlohmann::json _response)
        {
            response = std::move(_response);
            send_response();
        }

        //  Response Data:
        //  bt-encoded are converted in real-time
        //    - bool becomes 0 or 1
        //    - key:value where value == null are omitted
        //    - other nulls will raise an exception if found in json
        //    - no doubles
        //      - to store doubles: encode bt in endpoint-specific way
        //    - binary strings will fail json serialization; caller must
        //
        //        std::string binary = some_binary_data();
        //        request.response["binary_value"] = is_bt ? binary : oxenmq::to_hex(binary)
        //
        nlohmann::json response;

        //  Proxy Object:
        //  Sets binary data in "response"
        //    - if return type is json, encodes as hex
        //    - if return type is bt, then binary is untouched
        //
        //  Usage:
        //    std::string data = "abc";
        //    request.response_hex["foo"]["bar"] = data; // json: "616263", bt: "abc"
        //
        llarp::rpc::json_binary_proxy response_hex{response, llarp::rpc::json_binary_proxy::fmt::hex};

        //  Proxy Object:
        //  Encodes binary data as base_64 for json-encoded responses, leaves as binary for
        //  bt-encoded responses
        //
        //    Usage:
        //      std::string data = "abc"
        //      request.response_b64["foo"]["bar"] = data; json: "YWJj", bt: "abc"
        //
        llarp::rpc::json_binary_proxy response_b64{response, llarp::rpc::json_binary_proxy::fmt::base64};

        //  The oxenmq deferred send object into which the response will be sent when the `invoke`
        //  method returns.  If the response needs to happen later (i.e. not immediately after
        //  `invoke` returns) then you should call `defer()` to extract and clear this and then send
        //  the response via the returned DeferredSend object yourself.
        std::optional<oxenmq::Message::DeferredSend> replier;

        // Called to clear the current replier and return it.  After this call the automatic reply
        // will not be generated; the caller is responsible for calling `->reply` on the returned
        // optional itself.  This is typically used where a call has to be deferred, for example
        // because it depends on some network response to build the reply.
        oxenmq::Message::DeferredSend move()
        {
            auto r{std::move(*replier)};
            replier.reset();
            return r;
        }
    };

    //  Tag types that are inherited to set RPC endpoint properties

    //  RPC call wil take no input arguments
    //    Parameter dict can be passed, but will be ignored
    struct NoArgs : virtual RPCRequest
    {};

    // RPC call will be executed immediately
    struct Immediate : virtual RPCRequest
    {};

}  // namespace llarp::rpc
