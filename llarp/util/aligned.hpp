#pragma once

#include "bencode.h"
#include "llarp/util/str.hpp"
#include "llarp/util/types.hpp"
#include <cstdint>
#include <functional>
#include <llarp/util/logging.hpp>
#include <llarp/util/formattable.hpp>

#include <oxenc/hex.h>
#include <sodium/utils.h>

#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <algorithm>
#include <typeinfo>
#include <valarray>

extern "C"
{
  extern void
  randombytes(unsigned char* const ptr, unsigned long long sz);

  extern int
  sodium_is_zero(const unsigned char* n, const size_t nlen);
}
namespace llarp
{
  /// aligned buffer that is sz bytes long and aligns to the nearest Alignment
  template <size_t sz>
  // Microsoft C malloc(3C) cannot return pointers aligned wider than 8 ffs
#ifdef _WIN32
  struct alignas(uint64_t) AlignedBuffer
#else
  struct alignas(std::max_align_t) AlignedBuffer
#endif
  {
    static_assert(alignof(std::max_align_t) <= 16, "insane alignment");
    static_assert(
        sz >= 8,
        "AlignedBuffer cannot be used with buffers smaller than 8 "
        "bytes");
    static inline constexpr auto SIZE = sz;
    using Data = std::array<byte_t, sz>;

    AlignedBuffer() = default;

    explicit AlignedBuffer(const byte_t* data) : AlignedBuffer<sz>{}
    {
      for (size_t idx = 0; idx < size(); ++idx)
        m_data[idx] = data[idx];
    }

    constexpr explicit AlignedBuffer(const Data& buf) : m_data{buf}
    {}

    constexpr explicit AlignedBuffer(Data&& buf) : m_data{buf}
    {}

    AlignedBuffer&
    operator=(const byte_t* data)
    {
      std::memcpy(m_data.data(), data, sz);
      return *this;
    }

    /// bitwise NOT
    constexpr AlignedBuffer<sz>
    operator~() const
    {
      AlignedBuffer<sz> other{};
      std::transform(begin(), end(), other.data(), std::bit_not<>());
      return other;
    }

    constexpr bool
    operator==(const AlignedBuffer& other) const
    {
      return m_data == other.m_data;
    }

    constexpr bool
    operator!=(const AlignedBuffer& other) const
    {
      return not(*this == other);
    }

    constexpr bool
    operator<(const AlignedBuffer& other) const
    {
      return m_data < other.m_data;
    }

    constexpr bool
    operator>(const AlignedBuffer& other) const
    {
      return m_data > other.m_data;
    }

    constexpr bool
    operator<=(const AlignedBuffer& other) const
    {
      return m_data <= other.m_data;
    }

    constexpr bool
    operator>=(const AlignedBuffer& other) const
    {
      return m_data >= other.m_data;
    }

    constexpr AlignedBuffer
    operator^(const AlignedBuffer& other) const
    {
      AlignedBuffer<sz> copy{m_data};
      copy ^= other;
      return other;
    }

    constexpr AlignedBuffer&
    operator^=(const AlignedBuffer& other)
    {
      std::transform(other.begin(), other.end(), begin(), end(), std::bit_xor<>());
      return *this;
    }

    inline byte_t&
    operator[](size_t idx)
    {
      return m_data[idx];
    }

    inline const byte_t&
    operator[](size_t idx) const
    {
      return m_data[idx];
    }

    static constexpr size_t
    size()
    {
      return sz;
    }

    constexpr void
    Fill(byte_t f)
    {
      m_data.fill(f);
    }

    constexpr Data&
    as_array()
    {
      return m_data;
    }

    constexpr const Data&
    as_array() const
    {
      return m_data;
    }

    constexpr byte_t*
    data()
    {
      return m_data.data();
    }

    constexpr const byte_t*
    data() const
    {
      return m_data.data();
    }

    bool
    IsZero() const
    {
      return sodium_is_zero(data(), size());
    }

    void
    Zero()
    {
      sodium_memzero(data(), size());
    }

    virtual void
    Randomize()
    {
      randombytes(data(), size());
    }

    constexpr typename Data::iterator
    begin()
    {
      return m_data.begin();
    }

    constexpr typename Data::iterator
    end()
    {
      return m_data.end();
    }

    constexpr typename Data::const_iterator
    begin() const
    {
      return m_data.begin();
    }

    constexpr typename Data::const_iterator
    end() const
    {
      return m_data.end();
    }

    constexpr std::string_view
    ToView() const
    {
      return std::string_view{reinterpret_cast<const char*>(data()), size()};
    }
    bool
    FromBytestring(llarp_buffer_t* buf)
    {
      if (buf->sz != sz)
      {
        llarp::LogError("bdecode buffer size mismatch ", buf->sz, "!=", sz);
        return false;
      }
      memcpy(data(), buf->base, sz);
      return true;
    }

    bool
    BEncode(llarp_buffer_t* buf) const
    {
      return bencode_write_bytestring(buf, data(), sz);
    }

    bool
    BDecode(llarp_buffer_t* buf)
    {
      llarp_buffer_t strbuf;
      if (!bencode_read_string(buf, &strbuf))
      {
        return false;
      }
      return FromBytestring(&strbuf);
    }

    std::string
    ToHex() const
    {
      return oxenc::to_hex(begin(), end());
    }

    std::string
    ShortHex() const
    {
      return oxenc::to_hex(begin(), begin() + 4);
    }

    bool
    FromHex(std::string_view str)
    {
      if (str.size() != 2 * size() || !oxenc::is_hex(str))
        return false;
      oxenc::from_hex(str.begin(), str.end(), begin());
      return true;
    }

   private:
    Data m_data;
  };

  namespace detail
  {
    template <size_t Sz>
    static std::true_type
    is_aligned_buffer_impl(AlignedBuffer<Sz>*);

    static std::false_type
    is_aligned_buffer_impl(...);
  }  // namespace detail

  // True if T is or is derived from AlignedBuffer<N> for any N
  template <typename T>
  constexpr inline bool is_aligned_buffer =
      decltype(detail::is_aligned_buffer_impl(static_cast<T*>(nullptr)))::value;

}  // namespace llarp

namespace fmt
{
  // Any AlignedBuffer<N> (or subclass) gets hex formatted when output:
  template <typename T>
  struct formatter<
      T,
      char,
      std::enable_if_t<llarp::is_aligned_buffer<T> && !llarp::IsToStringFormattable<T>>>
      : formatter<std::string_view>
  {
    template <typename FormatContext>
    auto
    format(const T& val, FormatContext& ctx)
    {
      auto it = oxenc::hex_encoder{val.begin(), val.end()};
      return std::copy(it, it.end(), ctx.out());
    }
  };
}  // namespace fmt

namespace std
{
  template <size_t sz>
  struct hash<llarp::AlignedBuffer<sz>>
  {
    std::size_t
    operator()(const llarp::AlignedBuffer<sz>& buf) const noexcept
    {
      std::size_t h = 0;
      std::memcpy(&h, buf.data(), sizeof(std::size_t));
      return h;
    }
  };
}  // namespace std
