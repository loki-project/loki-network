#ifndef LLARP_IWP_MESSAGE_BUFFER_HPP
#define LLARP_IWP_MESSAGE_BUFFER_HPP
#include <vector>
#include <constants/link_layer.hpp>
#include <link/session.hpp>
#include <util/aligned.hpp>
#include <util/buffer.hpp>
#include <util/types.hpp>

namespace llarp
{
  namespace iwp
  {
    enum Command
    {
      /// keep alive message
      ePING = 0,
      /// begin transission
      eXMIT = 1,
      /// fragment data
      eDATA = 2,
      /// acknolege fragments
      eACKS = 3,
      /// close session
      eCLOS = 4
    };

    static constexpr size_t FragmentSize = 1024;

    struct OutboundMessage
    {
      OutboundMessage();
      OutboundMessage(uint64_t msgid, const llarp_buffer_t& pkt,
                      ILinkSession::CompletionHandler handler);

      AlignedBuffer< MAX_LINK_MSG_SIZE > m_Data;
      uint16_t m_Size = 0;
      uint64_t m_MsgID = 0;
      std::bitset< MAX_LINK_MSG_SIZE / FragmentSize > m_Acks;
      ILinkSession::CompletionHandler m_Completed;
      llarp_time_t m_LastFlush = 0;

      std::vector<byte_t>
      XMIT() const;

      void
      Ack(byte_t bitmask);

      void 
      FlushUnAcked(std::function<void(const llarp_buffer_t &)> sendpkt, llarp_time_t now);

      bool 
      ShouldFlush(llarp_time_t now) const;

      void
      Completed();

      bool
      IsTransmitted() const;
    };

    struct InboundMessage
    {
      InboundMessage();
      InboundMessage(uint64_t msgid, uint16_t sz, ShortHash h);

      AlignedBuffer< MAX_LINK_MSG_SIZE > m_Data;
      ShortHash m_Digset;
      uint16_t m_Size = 0;
      uint64_t m_MsgID = 0;
      llarp_time_t m_LastACKSent = 0;
      std::bitset< MAX_LINK_MSG_SIZE / FragmentSize > m_Acks;

      void
      HandleData(uint16_t idx, const byte_t * ptr);

      bool 
      IsCompleted() const;

      bool 
      Verify() const;

      bool 
      ShouldSendACKS(llarp_time_t now) const;

      void 
      SendACKS(std::function<void(const llarp_buffer_t &)> sendpkt, llarp_time_t now);

      std::vector<byte_t>
      ACKS() const;

    };

  }  // namespace iwp
}  // namespace llarp

#endif