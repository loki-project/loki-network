#pragma once

#include "identity.hpp"
// #include "info.hpp"
#include "intro.hpp"

#include <llarp/crypto/encrypted.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/ev/loop.hpp>
#include <llarp/path/pathhandler.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/util/time.hpp>

#include <vector>

struct llarp_threadpool;

/** TODO:
    - All of the references to service::Endpoint must be changed to EndpointBase
    - Now that there are four objects handling local/remote hidden service/exit node sessions,
      each of the four will need to handle ProtocolMessage objects and the ProtocolMessageFrames
      that contain them
*/

namespace llarp
{
    namespace path
    {
        /// forward declare
        struct Path;
    }  // namespace path

    namespace service
    {
        struct Endpoint;

        inline constexpr std::size_t MAX_PROTOCOL_MESSAGE_SIZE{4096};

        /// inner message
        struct ProtocolMessage
        {
            ProtocolMessage(const SessionTag& tag);
            ProtocolMessage();
            ~ProtocolMessage();
            ProtocolType proto = ProtocolType::TrafficV4;
            std::chrono::milliseconds queued = 0s;
            std::vector<uint8_t> payload;  // encrypted AbstractLinkMessage
            Introduction intro_reply;
            ServiceInfo sender;
            Endpoint* handler = nullptr;
            SessionTag tag;
            std::chrono::milliseconds creation_time{time_now_ms()};

            /// encode metainfo for lmq endpoint auth
            std::vector<char> encode_auth_info() const;

            std::string bt_encode() const;

            bool bt_decode(std::string_view buf);

            void bt_decode(oxenc::bt_dict_consumer& btdc);

            void put_buffer(std::string buf);

            static void process_async(std::shared_ptr<path::Path> p, HopID from, std::shared_ptr<ProtocolMessage> self);

            bool operator>(const ProtocolMessage& other) const
            {
                return creation_time > other.creation_time;
            }
        };

        /// outer message
        struct ProtocolFrameMessage
        {
            PQCipherBlock cipher;
            Encrypted<2048> enc;
            uint64_t flag;  // set to indicate in plaintext a nack, aka "dont try again"
            SymmNonce nonce;
            Signature sig;
            HopID path_id;
            service::SessionTag convo_tag;

            ProtocolFrameMessage(const ProtocolFrameMessage& other) = default;

            ProtocolFrameMessage()
            {
                clear();
            }

            ~ProtocolFrameMessage() = default;

            bool operator==(const ProtocolFrameMessage& other) const;

            bool operator!=(const ProtocolFrameMessage& other) const
            {
                return !(*this == other);
            }

            ProtocolFrameMessage& operator=(const ProtocolFrameMessage& other) = default;

            bool encrypt_and_sign(
                const ProtocolMessage& msg, const SharedSecret& sharedkey, const Identity& localIdent);

            bool sign(const Identity& localIdent);

            bool async_decrypt_verify(
                std::shared_ptr<path::Path> fromPath,
                const Identity& localIdent,
                Endpoint* handler,
                std::function<void(std::shared_ptr<ProtocolMessage>)> hook = nullptr) const;

            bool decrypt_payload_to_message(const SharedSecret& sharedkey, ProtocolMessage& into) const;

            /** Note: this method needs to be re-examined where it is called in the other class
               methods, like ::Sign(), ::EncryptAndSign(), and ::Verify(). In all 3 of these cases,
               the subsequent methods that the llarp_buffer_t is passed to must be refactored to
               take either a string, a redesigned llarp_buffer, or some span backport.
            */
            std::string bt_encode() const;

            void clear()
            {
                cipher.zero();
                enc.Clear();
                path_id.zero();
                convo_tag.zero();
                nonce.zero();
                sig.zero();
                flag = 0;
            }

            bool verify(const ServiceInfo& from) const;

            bool handle_message(Router* r) const;
        };
    }  // namespace service
}  // namespace llarp
