#include "stream.hpp"
#include "connection.hpp"
#include "endpoint.hpp"
#include <llarp/util/logging.hpp>

#include <cassert>
#include <iostream>

// We use a single circular buffer with a pointer to the starting byte (denoted `á` or `ŕ`), the
// overall size, and the number of sent-but-unacked bytes (denoted `a`).  `r` denotes an unsent
// byte.
//     [       áaaaaaaarrrr       ]
//             ^                    == start
//             ------------         == size (== unacked + unsent bytes)
//             --------             == unacked_size
//                         ^        -- the next write starts here
//      ^^^^^^^            ^^^^^^^  -- unused buffer space
//
// we give ngtcp2 direct control over the unacked part of this buffer (it will let us know once the
// buffered data is no longer needed, i.e. once it is acknowledged by the remote side).
//
// The complication is that this buffer wraps, so if we write a bunch of data to the above it would
// end up looking like this:
//
//     [rrr    áaaaaaaarrrrrrrrrrr]
//
// This complicates things a bit, especially when returning the buffer to be written because we
// might have to return two separate string_views (the first would contain [rrrrrrrrrrr] and the
// second would contain [rrr]).  As soon as we pass those buffer pointers off to ngtcp2 then our
// buffer looks like:
//
//     [aaa    áaaaaaaaaaaaaaaaaaa]
//
// Once we get an acknowledgement from the other end of the QUIC connection we can move up B (the
// beginning of the buffer); for example, suppose it acknowledges the next 10 bytes and then the
// following 10; we'll have:
//
//     [aaa              áaaaaaaaa] -- first 10 acked
//     [ áa                       ] -- next 10 acked
//
// As a special case, if the buffer completely empties (i.e. all data is sent and acked) then we
// reset the starting bytes to the beginning of the buffer.

namespace llarp::quic
{
  std::string
  StreamID::ToString() const
  {
    return fmt::format("Str❰{}❱", id);
  }

  Stream::Stream(
      Connection& conn,
      data_callback_t data_cb,
      close_callback_t close_cb,
      size_t buffer_size,
      StreamID id)
      : data_callback{std::move(data_cb)}
      , close_callback{std::move(close_cb)}
      , conn{conn}
      , stream_id{std::move(id)}
      , buffer{buffer_size}
      , avail_trigger{conn.endpoint.get_loop()->resource<uvw::AsyncHandle>()}
  {
    avail_trigger->on<uvw::AsyncEvent>([this](auto&, auto&) { handle_unblocked(); });
  }

  Stream::Stream(Connection& conn, StreamID id, size_t buffer_size)
      : Stream{conn, nullptr, nullptr, buffer_size, std::move(id)}
  {}

  Stream::~Stream()
  {
    LogTrace("Destroying stream ", stream_id);
    if (avail_trigger)
    {
      avail_trigger->close();
      avail_trigger.reset();
    }
    bool was_closing = is_closing;
    is_closing = is_shutdown = true;
    if (!was_closing && close_callback)
      close_callback(*this, STREAM_ERROR_CONNECTION_EXPIRED);
  }

  void
  Stream::set_buffer_size(size_t size)
  {
    if (used() != 0)
      throw std::runtime_error{"Cannot update buffer size while buffer is in use"};
    if (size > 0 && size < 2048)
      size = 2048;

    buffer.resize(size);
    buffer.shrink_to_fit();
    start = size = unacked_size = 0;
  }

  size_t
  Stream::buffer_size() const
  {
    return buffer.empty() ? size + start  // start is the acked amount of the first buffer
                          : buffer.size();
  }

  bool
  Stream::append(bstring_view data)
  {
    assert(!buffer.empty());

    if (data.size() > available())
      return false;

    // When we are appending we have three cases:
    // - data doesn't fit -- we simply abort (return false, above).
    // - data fits between the buffer end and `]` -- simply append it and update size
    // - data is larger -- copy from the end up to `]`, then copy the rest into the beginning of the
    // buffer (i.e. after `[`).

    size_t wpos = (start + size) % buffer.size();
    if (wpos + data.size() > buffer.size())
    {
      // We are wrapping
      auto data_split = data.begin() + (buffer.size() - wpos);
      std::copy(data.begin(), data_split, buffer.begin() + wpos);
      std::copy(data_split, data.end(), buffer.begin());
      LogTrace(
          "Wrote ",
          data.size(),
          " bytes to buffer ranges [",
          wpos,
          ",",
          buffer.size(),
          ")+[0,",
          data.end() - data_split,
          ")");
    }
    else
    {
      // No wrap needs, it fits before the end:
      std::copy(data.begin(), data.end(), buffer.begin() + wpos);
      LogTrace(
          "Wrote ", data.size(), " bytes to buffer range [", wpos, ",", wpos + data.size(), ")");
    }
    size += data.size();
    LogTrace("New stream buffer: ", size, "/", buffer.size(), " bytes beginning at ", start);
    conn.io_ready();
    return true;
  }
  size_t
  Stream::append_any(bstring_view data)
  {
    if (size_t avail = available(); data.size() > avail)
      data.remove_suffix(data.size() - avail);
    [[maybe_unused]] bool appended = append(data);
    assert(appended);
    return data.size();
  }

  void
  Stream::append_buffer(const std::byte* buffer, size_t length)
  {
    assert(this->buffer.empty());
    user_buffers.emplace_back(buffer, length);
    size += length;
    conn.io_ready();
  }

  void
  Stream::acknowledge(size_t bytes)
  {
    // Frees bytes; e.g. acknowledge(3) changes:
    //     [  áaaaaarr  ]  to  [     áaarr  ]
    //     [aaarr     áa]  to  [ áarr       ]
    //     [  áaarrr    ]  to  [     ŕrr    ]
    //     [      áaa   ]  to  [´           ]  (i.e. empty buffer *and* reset start pos)
    //
    assert(bytes <= unacked_size && unacked_size <= size);

    LogTrace("Acked ", bytes, " bytes of ", unacked_size, "/", size, " unacked/total");

    unacked_size -= bytes;
    size -= bytes;
    if (!buffer.empty())
      start = size == 0 ? 0
                        : (start + bytes)
              % buffer.size();  // reset start to 0 (to reduce wrapping buffers) if empty
    else if (size == 0)
    {
      user_buffers.clear();
      start = 0;
    }
    else
    {
      while (bytes)
      {
        assert(!user_buffers.empty());
        assert(start < user_buffers.front().second);
        if (size_t remaining = user_buffers.front().second - start; bytes >= remaining)
        {
          user_buffers.pop_front();
          start = 0;
          bytes -= remaining;
        }
        else
        {
          start += bytes;
          bytes = 0;
        }
      }
    }

    if (!unblocked_callbacks.empty())
      available_ready();
  }

  auto
  get_buffer_it(
      std::deque<std::pair<std::unique_ptr<const std::byte[]>, size_t>>& bufs, size_t offset)
  {
    auto it = bufs.begin();
    while (offset >= it->second)
    {
      offset -= it->second;
      it++;
    }
    return std::make_pair(std::move(it), offset);
  }

  std::vector<bstring_view>
  Stream::pending()
  {
    std::vector<bstring_view> bufs;
    size_t rsize = unsent();
    if (!rsize)
      return bufs;
    if (!buffer.empty())
    {
      size_t rpos = (start + unacked_size) % buffer.size();
      if (size_t rend = rpos + rsize; rend <= buffer.size())
      {
        bufs.emplace_back(buffer.data() + rpos, rsize);
      }
      else
      {  // wrapping
        bufs.reserve(2);
        bufs.emplace_back(buffer.data() + rpos, buffer.size() - rpos);
        bufs.emplace_back(buffer.data(), rend % buffer.size());
      }
    }
    else
    {
      assert(!user_buffers.empty());  // If empty then unsent() should have been 0
      auto [it, offset] = get_buffer_it(user_buffers, start + unacked_size);
      bufs.reserve(std::distance(it, user_buffers.end()));
      assert(it != user_buffers.end());
      bufs.emplace_back(it->first.get() + offset, it->second - offset);
      for (++it; it != user_buffers.end(); ++it)
        bufs.emplace_back(it->first.get(), it->second);
    }
    return bufs;
  }

  void
  Stream::when_available(unblocked_callback_t unblocked_cb)
  {
    assert(available() == 0);
    unblocked_callbacks.push(std::move(unblocked_cb));
  }

  void
  Stream::handle_unblocked()
  {
    if (is_closing)
      return;
    if (buffer.empty())
    {
      while (!unblocked_callbacks.empty() && unblocked_callbacks.front()(*this))
        unblocked_callbacks.pop();
    }
    while (!unblocked_callbacks.empty() && available() > 0)
    {
      if (unblocked_callbacks.front()(*this))
        unblocked_callbacks.pop();
      else
        assert(available() == 0);
    }
    conn.io_ready();
  }

  void
  Stream::io_ready()
  {
    conn.io_ready();
  }

  void
  Stream::available_ready()
  {
    if (avail_trigger)
      avail_trigger->send();
  }

  void
  Stream::wrote(size_t bytes)
  {
    // Called to tell us we sent some bytes off, e.g. wrote(3) changes:
    //     [  áaarrrrrr  ]  or  [rr     áaar]
    // to:
    //     [  áaaaaarrr  ]  or  [aa     áaaa]
    LogTrace("wrote ", bytes, ", unsent=", unsent());
    assert(bytes <= unsent());
    unacked_size += bytes;
  }

  void
  Stream::close(std::optional<uint64_t> error_code)
  {
    LogDebug(
        "Closing ",
        stream_id,
        error_code ? " immediately with code " + std::to_string(*error_code) : " gracefully");

    if (is_shutdown)
      LogDebug("Stream is already shutting down");
    else if (error_code)
    {
      is_closing = is_shutdown = true;
      ngtcp2_conn_shutdown_stream(conn, stream_id.id, *error_code);
    }
    else if (is_closing)
      LogDebug("Stream is already closing");
    else
      is_closing = true;

    if (is_shutdown)
      data_callback = {};

    conn.io_ready();
  }

  void
  Stream::data(std::shared_ptr<void> data)
  {
    user_data = std::move(data);
  }

  void
  Stream::weak_data(std::weak_ptr<void> data)
  {
    user_data = std::move(data);
  }

}  // namespace llarp::quic
