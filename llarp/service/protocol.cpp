#include "protocol.hpp"

#include "endpoint.hpp"

#include <llarp/path/path.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>

#include <utility>

namespace llarp::service
{
    static auto logcat = log::Cat("Protocol");

    ProtocolMessage::ProtocolMessage()
    {
        tag.zero();
    }

    ProtocolMessage::ProtocolMessage(const SessionTag& t) : tag(t)
    {}

    ProtocolMessage::~ProtocolMessage() = default;

    void ProtocolMessage::put_buffer(std::string buf)
    {
        payload.resize(buf.size());
        memcpy(payload.data(), buf.data(), buf.size());
    }

    void ProtocolMessage::process_async(
        std::shared_ptr<path::Path> path, HopID from, std::shared_ptr<ProtocolMessage> self)
    {
        (void)path;
        (void)from;
        (void)self;
        // if (!self->handler->HandleDataMessage(path, from, self))
        //   LogWarn("failed to handle data message from ", path->name());
    }

    bool ProtocolMessage::bt_decode(std::string_view buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};
            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "ProtocolMessage parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }

        return true;
    }

    void ProtocolMessage::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            proto = ProtocolType{btdc.require<uint64_t>("p")};

            if (auto maybe_payload = btdc.maybe<ustring>("d"))
            {
                payload = std::vector<uint8_t>(*maybe_payload->data(), maybe_payload->size());
            }

            {
                auto [key, subdict] = btdc.next_dict_consumer();

                if (key != "i")
                    throw std::invalid_argument{"Unexpected key (expected:'i', actual:'{}')"_format(key)};

                intro_reply.bt_decode(subdict);
            }

            {
                auto [key, subdict] = btdc.next_dict_consumer();

                if (key != "s")
                    throw std::invalid_argument{"Unexpected key (expected:'s', actual:'{}')"_format(key)};

                sender.bt_decode(subdict);
            }

            tag.from_string(btdc.require<std::string>("t"));
        }
        catch (...)
        {
            log::critical(logcat, "ProtocolMessage failed to populate with bt encoded contents");
            throw;
        }
    }

    std::string ProtocolMessage::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        try
        {
            btdp.append("a", static_cast<uint64_t>(proto));

            if (not payload.empty())
                btdp.append("d", std::string_view{reinterpret_cast<const char*>(payload.data()), payload.size()});

            {
                auto subdict = btdp.append_dict("i");
                intro_reply.bt_encode(subdict);
            }

            {
                auto subdict = btdp.append_dict("s");
                sender.bt_encode(subdict);
            }

            btdp.append("t", tag.to_view());
        }
        catch (...)
        {
            log::critical(logcat, "Error: ProtocolMessage failed to bt encode contents!");
        }

        return std::move(btdp).str();
    }

    std::vector<char> ProtocolMessage::encode_auth_info() const
    {
        oxenc::bt_dict_producer btdp;

        try
        {
            // btdp.append("a", static_cast<uint64_t>(proto));

            {
                auto subdict = btdp.append_dict("s");
                sender.bt_encode(subdict);
            }

            btdp.append("t", tag.to_view());
        }
        catch (...)
        {
            log::critical(logcat, "Error: ProtocolMessage failed to bt encode auth info");
        }

        auto view = btdp.view();
        std::vector<char> data;
        data.resize(view.size());

        std::copy_n(view.data(), view.size(), data.data());
        return data;
    }

    std::string ProtocolFrameMessage::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        try
        {
            btdp.append("A", "H");
            btdp.append("C", cipher.to_view());
            btdp.append("D", std::string_view{reinterpret_cast<const char*>(enc.data()), enc.size()});
            btdp.append("F", path_id.to_view());
            btdp.append("N", nonce.to_view());
            btdp.append("R", flag);
            btdp.append("T", convo_tag.to_view());
            btdp.append("Z", sig.to_view());
        }
        catch (...)
        {
            log::critical(logcat, "Error: ProtocolFrameMessage failed to bt encode contents!");
        }

        return std::move(btdp).str();
    }

    bool ProtocolFrameMessage::decrypt_payload_to_message(const SharedSecret& sharedkey, ProtocolMessage& msg) const
    {
        Encrypted<2048> tmp = enc;
        crypto::xchacha20(tmp.data(), tmp.size(), sharedkey, nonce);

        auto buf = tmp.to_string();

        return msg.bt_decode(buf);
    }

    bool ProtocolFrameMessage::sign(const Identity& localIdent)
    {
        sig.zero();
        std::array<uint8_t, MAX_PROTOCOL_MESSAGE_SIZE> tmp;
        llarp_buffer_t buf(tmp);
        // encode
        auto bte = bt_encode();
        buf.write(bte.begin(), bte.end());

        // rewind
        buf.sz = buf.cur - buf.base;
        buf.cur = buf.base;
        // sign
        return localIdent.Sign(sig, reinterpret_cast<uint8_t*>(bte.data()), bte.size());
    }

    bool ProtocolFrameMessage::encrypt_and_sign(
        const ProtocolMessage& msg, const SharedSecret& sessionKey, const Identity& localIdent)
    {
        // encode message
        auto bte1 = msg.bt_encode();
        // encrypt
        crypto::xchacha20(reinterpret_cast<uint8_t*>(bte1.data()), bte1.size(), sessionKey, nonce);
        // put encrypted buffer
        std::memcpy(enc.data(), bte1.data(), bte1.size());
        // zero out signature
        sig.zero();

        auto bte2 = bt_encode();
        // sign
        if (!localIdent.Sign(sig, reinterpret_cast<uint8_t*>(bte2.data()), bte2.size()))
        {
            log::error(logcat, "ProtocolFrameMessage failed to sign with local identity key!");
            return false;
        }
        return true;
    }

    struct AsyncFrameDecrypt
    {
        std::shared_ptr<path::Path> path;
        std::shared_ptr<ProtocolMessage> msg;
        const Identity& _local_identity;
        Endpoint* handler;
        const ProtocolFrameMessage frame;
        const Introduction src_intro;

        AsyncFrameDecrypt(
            const Identity& localIdent,
            Endpoint* h,
            std::shared_ptr<ProtocolMessage> m,
            const ProtocolFrameMessage& f,
            const Introduction& recvIntro)
            : msg(std::move(m)), _local_identity(localIdent), handler(h), frame(f), src_intro(recvIntro)
        {}

        static void work(std::shared_ptr<AsyncFrameDecrypt> self)
        {
            SharedSecret K;
            SharedSecret shared_key;
            // copy
            ProtocolFrameMessage frame(self->frame);
            if (!crypto::pqe_decrypt(self->frame.cipher, K, pq_keypair_to_seckey(self->_local_identity.pq)))
            {
                log::error(logcat, "pqe_decrypt failed (cipher:{})", self->frame.cipher);
                self->msg.reset();
                return;
            }
            // decrypt
            // auto buf = frame.enc.Buffer();
            uint8_t* buf = frame.enc.data();
            size_t sz = frame.enc.size();
            crypto::xchacha20(buf, sz, K, self->frame.nonce);

            auto bte = self->msg->bt_encode();

            if (bte.empty())
            {
                log::error(logcat, "Failed to decode inner protocol message");
                // DumpBuffer(*buf);
                self->msg.reset();
                return;
            }

            // verify signature of outer message after we parsed the inner message
            if (!self->frame.verify(self->msg->sender))
            {
                log::error(
                    logcat,
                    "Intro frame has invalid signature (sig:{}, from:{})",
                    self->frame.sig,
                    self->msg->sender.address());
                self->msg.reset();
                return;
            }

            // if (self->handler->HasConvoTag(self->msg->tag))
            // {
            //   LogError("dropping duplicate convo tag T=", self->msg->tag);
            //   // TODO: send convotag reset
            //   self->msg.reset();
            //   return;
            // }

            // PKE (A, B, N)
            SharedSecret shared_secret;

            if (!crypto::dh_server(
                    shared_secret,
                    self->msg->sender.encryption_pubkey(),
                    self->_local_identity.enckey,
                    self->frame.nonce))
            {
                log::error(logcat, "X25519 key exchange failed!");
                self->msg.reset();
                return;
            }
            std::array<uint8_t, 64> tmp;
            // K
            std::memcpy(tmp.begin(), K.begin(), K.size());
            // S = HS( K + PKE( A, B, N))
            std::memcpy(tmp.begin() + 32, shared_secret.begin(), shared_secret.size());

            crypto::shorthash(shared_key, tmp.data(), tmp.size());

            std::shared_ptr<ProtocolMessage> msg = std::move(self->msg);
            std::shared_ptr<path::Path> path = std::move(self->path);
            const HopID from = self->frame.path_id;
            msg->handler = self->handler;
            // self->handler->AsyncProcessAuthMessage(
            //     msg,
            //     [path, msg, from, handler = self->handler, fromIntro = self->fromIntro,
            //     shared_key](
            //         std::string result, bool success) {
            //       if (success)
            //       {
            //         if (handler->WantsOutboundSession(msg->sender.Addr()))
            //         {
            //           handler->PutSenderFor(msg->tag, msg->sender, false);
            //         }
            //         else
            //         {
            //           handler->PutSenderFor(msg->tag, msg->sender, true);
            //         }
            //         handler->PutReplyIntroFor(msg->tag, msg->introReply);
            //         handler->PutCachedSessionKeyFor(msg->tag, shared_key);
            //         handler->SendAuthResult(path, from, msg->tag, result, success);

            //         log::info(
            //             logcat, "Auth accepted for tag {} from sender {}", msg->tag,
            //             msg->sender.Addr());
            //         ProtocolMessage::ProcessAsync(path, from, msg);
            //       }
            //       else
            //       {
            //         log::warning(logcat, "Auth invalid for tag {} (code: {})", msg->tag, result);
            //       }

            //       handler->Pump(time_now_ms());
            //     });
        }
    };

    struct AsyncDecrypt
    {
        ServiceInfo si;
        SharedSecret shared;
        ProtocolFrameMessage frame;
    };

    bool ProtocolFrameMessage::async_decrypt_verify(
        std::shared_ptr<path::Path> recvPath,
        const Identity& localIdent,
        Endpoint* handler,
        std::function<void(std::shared_ptr<ProtocolMessage>)> hook) const
    {
        auto msg = std::make_shared<ProtocolMessage>();
        msg->handler = handler;
        if (convo_tag.is_zero())
        {
            // we need to dh
            auto dh = std::make_shared<AsyncFrameDecrypt>(localIdent, handler, msg, *this, recvPath->intro);
            dh->path = recvPath;
            handler->router().queue_work([dh = std::move(dh)] { return AsyncFrameDecrypt::work(dh); });
            return true;
        }

        auto v = std::make_shared<AsyncDecrypt>();

        // if (!handler->GetCachedSessionKeyFor(convo_tag, v->shared))
        // {
        //   LogError("No cached session for T=", convo_tag);
        //   return false;
        // }
        // if (v->shared.IsZero())
        // {
        //   LogError("bad cached session key for T=", convo_tag);
        //   return false;
        // }

        // if (!handler->GetSenderFor(convo_tag, v->si))
        // {
        //   LogError("No sender for T=", convo_tag);
        //   return false;
        // }
        // if (v->si.Addr().IsZero())
        // {
        //   LogError("Bad sender for T=", convo_tag);
        //   return false;
        // }

        v->frame = *this;
        auto callback = [loop = handler->loop(), hook](std::shared_ptr<ProtocolMessage> msg) {
            if (hook)
            {
                loop->call([msg, hook]() { hook(msg); });
            }
        };
        // handler->router()->queue_work(
        //     [v, msg = std::move(msg), recvPath = std::move(recvPath), callback, handler]() {
        //       auto resetTag =
        //           [handler, tag = v->frame.convo_tag, from = v->frame.path_id, path = recvPath]()
        //           {
        //             handler->ResetConvoTag(tag, path, from);
        //           };

        //       if (not v->frame.Verify(v->si))
        //       {
        //         LogError("Signature failure from ", v->si.Addr());
        //         handler->Loop()->call_soon(resetTag);
        //         return;
        //       }
        //       if (not v->frame.DecryptPayloadInto(v->shared, *msg))
        //       {
        //         LogError("failed to decrypt message from ", v->si.Addr());
        //         handler->Loop()->call_soon(resetTag);
        //         return;
        //       }
        //       callback(msg);
        //       RecvDataEvent ev;
        //       ev.fromPath = std::move(recvPath);
        //       ev.pathid = v->frame.path_id;
        //       auto* handler = msg->handler;
        //       ev.msg = std::move(msg);
        //       handler->QueueRecvData(std::move(ev));
        //     });
        return true;
    }

    bool ProtocolFrameMessage::operator==(const ProtocolFrameMessage& other) const
    {
        return cipher == other.cipher && enc == other.enc && nonce == other.nonce && sig == other.sig
            && convo_tag == other.convo_tag;
    }

    bool ProtocolFrameMessage::verify(const ServiceInfo& svc) const
    {
        ProtocolFrameMessage copy(*this);
        copy.sig.zero();

        auto bte = copy.bt_encode();
        return svc.verify(reinterpret_cast<uint8_t*>(bte.data()), bte.size(), sig);
    }

    bool ProtocolFrameMessage::handle_message(Router* /*r*/) const
    {
        return true;
    }

}  // namespace llarp::service
