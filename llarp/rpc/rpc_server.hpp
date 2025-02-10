#pragma once

#include "json_bt.hpp"
#include "rpc_request_definitions.hpp"

#include <llarp/config/config.hpp>

#include <nlohmann/json_fwd.hpp>
#include <oxen/log/omq_logger.hpp>
#include <oxenmq/address.h>
#include <oxenmq/message.h>
#include <oxenmq/oxenmq.h>

// #include <stdexcept>
// #include <string_view>

namespace llarp
{
    struct Router;

    namespace rpc
    {

        class RPCServer;

        //  Stores RPC request callback
        struct rpc_callback
        {
            using result_type = std::variant<oxenc::bt_value, nlohmann::json, std::string>;
            //  calls with incoming request data; returns response body or throws exception
            void (*invoke)(oxenmq::Message&, RPCServer&);
        };

        //  RPC request registration
        //    Stores references to RPC requests in a unordered map for ease of reference
        //    when adding to server. To add endpoints, define in rpc_request_definitions.hpp
        //    and register in rpc_server.cpp
        extern const std::unordered_map<std::string, rpc_callback> rpc_request_map;

        //  Exception used to signal various types of errors with a request back to the caller.  This
        //  exception indicates that the caller did something wrong: bad data, invalid value, etc., but
        //  don't indicate a local problem (and so we'll log them only at debug).  For more serious,
        //  internal errors a command should throw some other stl error (e.g. std::runtime_error or
        //  perhaps std::logic_error), which will result in a local daemon warning (and a generic
        //  internal error response to the user).
        //
        //  For JSON RPC these become an error response with the code as the error.code value and the
        //  string as the error.message.
        //  For HTTP JSON these become a 500 Internal Server Error response with the message as the
        //  body. For OxenMQ the code becomes the first part of the response and the message becomes the
        //  second part of the response.
        struct rpc_error : std::runtime_error
        {
            /// \param message - a message to send along with the error code (see general description
            /// above).
            rpc_error(std::string message) : std::runtime_error{"RPC error: " + message}, message{std::move(message)} {}

            std::string message;
        };

        template <typename Result_t>
        void SetJSONResponse(Result_t result, json& j)
        {
            j["result"] = result;
        }

        inline void SetJSONError(std::string_view msg, json& j) { j["error"] = msg; }

        class RPCServer
        {
          public:
            explicit RPCServer(std::shared_ptr<oxenmq::OxenMQ>, Router&);
            ~RPCServer() = default;

            void HandleLogsSubRequest(oxenmq::Message& m);

            void AddCategories();

            void invoke(FindCC& findcc);
            void invoke(SessionInit& sessioninit);
            void invoke(SessionClose& sessionclose);
            void invoke(Status& status);

            void invoke(LookupSnode& lookupsnode);
            void invoke(Halt& halt);
            void invoke(Version& version);
            void invoke(GetStatus& getstatus);
            void invoke(QuicConnect& quicconnect);
            void invoke(QuicListener& quiclistener);
            void invoke(MapExit& mapexit);
            void invoke(ListExits& listexits);
            void invoke(UnmapExit& unmapexit);
            void invoke(SwapExits& swapexits);
            void invoke(DNSQuery& dnsquery);
            void invoke(Config& config);

            std::shared_ptr<oxenmq::OxenMQ> m_LMQ;
            Router& _router;
            oxen::log::PubsubLogger log_subs;
        };

        template <typename RPC>
        class EndpointHandler
        {
          public:
            RPCServer& server;
            RPC rpc{};

            EndpointHandler(RPCServer& _server, oxenmq::Message::DeferredSend _replier) : server{_server}
            {
                rpc.replier.emplace(std::move(_replier));
            }

            void operator()()
            {
                try
                {
                    server.invoke(rpc);
                }
                catch (const rpc_error& e)
                {
                    SetJSONError("RPC request 'rpc.{}' failed with: {}"_format(rpc.name, e.what()), rpc.response);
                }
                catch (const std::exception& e)
                {
                    SetJSONError(
                        "RPC request 'rpc.{}' raised an exception: {}"_format(rpc.name, e.what()), rpc.response);
                }

                if (rpc.replier.has_value())
                {
                    rpc.send_response();
                }
            }
        };
    }  // namespace rpc
}  // namespace llarp
