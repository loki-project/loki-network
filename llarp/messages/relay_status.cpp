#include <messages/relay_status.hpp>

#include <crypto/crypto.hpp>
#include <path/path_context.hpp>
#include <path/ihophandler.hpp>
#include <router/abstractrouter.hpp>
#include <routing/path_confirm_message.hpp>
#include <util/bencode.hpp>
#include <util/buffer.hpp>
#include <util/logger.hpp>
#include <util/logic.hpp>

#include <functional>

namespace llarp
{
  struct LRSM_AsyncHandler : public std::enable_shared_from_this< LRSM_AsyncHandler >
  {
    using HopHandler_ptr = std::shared_ptr< llarp::path::IHopHandler >;

    std::array< EncryptedFrame, 8 > frames;
    PathID_t pathid;
    uint64_t status = 0;
    HopHandler_ptr path;
    AbstractRouter *router;

    LRSM_AsyncHandler(const std::array< EncryptedFrame, 8> &_frames,
                      const PathID_t& _pathid, uint64_t _status,
                      HopHandler_ptr _path, AbstractRouter *_router)
        : frames(_frames), pathid(_pathid), status(_status), path(_path), router(_router)
    {
    }

    ~LRSM_AsyncHandler()
    {
    }

    void handle()
    {
      path->HandleLRSM(status, frames, router);
    }

    void queue_handle()
    {
      auto func = std::bind(&llarp::LRSM_AsyncHandler::handle, shared_from_this());
      llarp_threadpool_queue_job(router->pathContext().Worker(), func);
    }

  };


  LR_StatusMessage::~LR_StatusMessage()
  {
  }

  bool
  LR_StatusMessage::DecodeKey(const llarp_buffer_t& key, llarp_buffer_t* buf)
  {
    bool read = false;
    if(key == "c")
    {
      return BEncodeReadArray(frames, buf);
    }
    else if(key == "p")
    {
      if (!BEncodeMaybeReadDictEntry("p", pathid, read, key, buf))
      {
        return false;
      }
    }
    else if(key == "s")
    {
      if (!BEncodeMaybeReadDictInt("s", status, read, key, buf))
      {
        return false;
      }
    }
    else if(key == "v")
    {
      if(!BEncodeMaybeReadVersion("v", version, LLARP_PROTO_VERSION, read, key,
                                  buf))
      {
        return false;
      }
    }

    return read;
  }

  void
  LR_StatusMessage::Clear()
  {
    frames[0].Clear();
    frames[1].Clear();
    frames[2].Clear();
    frames[3].Clear();
    frames[4].Clear();
    frames[5].Clear();
    frames[6].Clear();
    frames[7].Clear();
  }

  bool
  LR_StatusMessage::BEncode(llarp_buffer_t* buf) const
  {
    if(!bencode_start_dict(buf))
      return false;
    // msg type
    if(!BEncodeWriteDictMsgType(buf, "a", "s"))
      return false;
    // frames
    if(!BEncodeWriteDictArray("c", frames, buf))
      return false;
    // path id
    if(!BEncodeWriteDictEntry("p", pathid, buf))
      return false;
    // status (for now, only success bit is relevant)
    if(!BEncodeWriteDictInt("s", status, buf))
      return false;
    // version
    if(!bencode_write_version_entry(buf))
      return false;

    return bencode_end(buf);
  }

  bool
  LR_StatusMessage::HandleMessage(AbstractRouter* router) const
  {
    llarp::LogDebug("Received LR_Status message from (", session->GetPubKey(), ")");
    if(frames.size() != path::max_len)
    {
      llarp::LogError("LRSM invalid number of records, ", frames.size(),
                      "!=", path::max_len);
      return false;
    }

    auto path = router->pathContext().GetByUpstream(session->GetPubKey(), pathid);
    if (!path)
    {
      llarp::LogWarn("unhandled LR_Status message: no associated IHopHandler found");
      return false;
    }

    auto handler = std::make_shared< LRSM_AsyncHandler >(
        frames, pathid, status, path, router);

    handler->queue_handle();

    return true;
  }

  void LR_StatusMessage::SetDummyFrames()
  {
    //TODO
    return;
  }

  // call this from a worker thread
  bool
  LR_StatusMessage::CreateAndSend(AbstractRouter *router, const PathID_t pathid,
                                  const RouterID nextHop, const SharedSecret pathKey,
                                  uint64_t status)
  {
    typedef std::shared_ptr< LR_StatusMessage > LRSM_ptr;
    LRSM_ptr message = std::make_shared< LR_StatusMessage >();

    message->status = status & LR_StatusRecord::SUCCESS;
    message->pathid = pathid;

    message->SetDummyFrames();

    if(!message->AddFrame(pathKey, status))
    {
      return false;
    }

    QueueSendMessage(router, nextHop, message);
    return true; // can't guarantee delivery here, as far as we know it's fine
  }

  bool
  LR_StatusMessage::AddFrame(const SharedSecret& pathKey, uint64_t status)
  {
    frames[7] = frames[6];
    frames[6] = frames[5];
    frames[5] = frames[4];
    frames[4] = frames[3];
    frames[3] = frames[2];
    frames[2] = frames[1];
    frames[1] = frames[0];

    auto& frame = frames[0];

    frame.Randomize();

    LR_StatusRecord record;

    record.status    = status;
    record.version     = LLARP_PROTO_VERSION;

    llarp_buffer_t buf(frame.data(), frame.size());
    buf.cur = buf.base + EncryptedFrameOverheadSize;
    // encode record
    if(!record.BEncode(&buf))
    {
      // failed to encode?
      LogError(Name(), " Failed to generate Status Record");
      DumpBuffer(buf);
      return false;
    }
    // use ephemeral keypair for frame
    if(!frame.DoEncrypt(pathKey, true))
    {
      LogError(Name(), " Failed to encrypt LRSR");
      DumpBuffer(buf);
      return false;
    }

    return true;
  }

  void
  LR_StatusMessage::QueueSendMessage(AbstractRouter *router, const RouterID nextHop,
                   std::shared_ptr< LR_StatusMessage > msg)
  {
    auto func = std::bind(&LR_StatusMessage::SendMessage, router, nextHop, msg); 
    router->pathContext().logic()->queue_func(func);
  }

  void
  LR_StatusMessage::SendMessage(AbstractRouter *router, const RouterID nextHop,
                                std::shared_ptr< LR_StatusMessage > msg)
  {
    llarp::LogDebug("Attempting to send LR_Status message to (", nextHop, ")");
    if(router->HasSessionTo(nextHop))
    {
      if (router->SendToOrQueue(nextHop, msg.get()))
      {
        return;
      }
      llarp::LogError("Sending LR_Status message, SendToOrQueue to ", nextHop, " failed");
      return;
    }
    llarp::LogError("Sending LR_Status message, but no connection to previous hop (", nextHop, ")");
    return;
  }

  bool
  LR_StatusRecord::BEncode(llarp_buffer_t* buf) const
  {
    if(!bencode_start_dict(buf))
      return false;

    if(!BEncodeWriteDictInt("s", status, buf))
      return false;
    if(!bencode_write_version_entry(buf))
      return false;

    return bencode_end(buf);
  }

  bool
  LR_StatusRecord::OnKey(llarp_buffer_t* buffer, llarp_buffer_t* key)
  {
    if(!key)
      return true;

    bool read = false;

    if(!BEncodeMaybeReadDictInt("s", status, read, *key, buffer))
      return false;
    if(!BEncodeMaybeReadVersion("v", version, LLARP_PROTO_VERSION, read, *key,
                                buffer))
      return false;

    return read;
  }

  bool
  LR_StatusRecord::BDecode(llarp_buffer_t* buf)
  {
    using namespace std::placeholders;
    return bencode_read_dict(std::bind(&LR_StatusRecord::OnKey, this, _1, _2),
                             buf);
  }

  bool
  LR_StatusRecord::operator==(const LR_StatusRecord& other) const
  {
    return status == other.status;
  }


}  // namespace llarp
