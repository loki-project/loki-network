#pragma once

#include "formattable.hpp"
#include "logging.hpp"
#include "random.hpp"

#include <oxenc/bt.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <type_traits>

extern "C"
{
    extern int sodium_is_zero(const unsigned char* n, const size_t nlen);
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

        static constexpr size_t SIZE = sz;

        virtual ~AlignedBuffer() = default;

        AlignedBuffer() { zero(); }

        AlignedBuffer(const uint8_t* data) { *this = data; }

        explicit AlignedBuffer(const std::array<uint8_t, SIZE>& buf) { _data = buf; }

        AlignedBuffer& operator=(const uint8_t* data)
        {
            std::memcpy(_data.data(), data, sz);
            return *this;
        }

        /// bitwise NOT
        AlignedBuffer<sz> operator~() const
        {
            AlignedBuffer<sz> ret;
            std::transform(begin(), end(), ret.begin(), [](uint8_t a) { return ~a; });

            return ret;
        }

        bool operator==(const AlignedBuffer& other) const { return _data == other._data; }

        bool operator!=(const AlignedBuffer& other) const { return _data != other._data; }

        bool operator<(const AlignedBuffer& other) const { return _data < other._data; }

        bool operator>(const AlignedBuffer& other) const { return _data > other._data; }

        bool operator<=(const AlignedBuffer& other) const { return _data <= other._data; }

        bool operator>=(const AlignedBuffer& other) const { return _data >= other._data; }

        AlignedBuffer operator^(const AlignedBuffer& other) const
        {
            AlignedBuffer<sz> ret;
            std::transform(begin(), end(), other.begin(), ret.begin(), std::bit_xor<>());
            return ret;
        }

        AlignedBuffer& operator^=(const AlignedBuffer& other)
        {
            // Mutate in place instead.
            for (size_t i = 0; i < sz; ++i)
            {
                _data[i] ^= other._data[i];
            }
            return *this;
        }

        uint8_t& operator[](size_t idx)
        {
            assert(idx < SIZE);
            return _data[idx];
        }

        const uint8_t& operator[](size_t idx) const
        {
            assert(idx < SIZE);
            return _data[idx];
        }

        static constexpr size_t size() { return sz; }

        void Fill(uint8_t f) { _data.fill(f); }

        std::array<uint8_t, SIZE>& as_array() { return _data; }

        const std::array<uint8_t, SIZE>& as_array() const { return _data; }

        uint8_t* data() { return _data.data(); }

        const uint8_t* data() const { return _data.data(); }

        bool is_zero() const
        {
            const uint64_t* ptr = reinterpret_cast<const uint64_t*>(data());
            for (size_t idx = 0; idx < SIZE / sizeof(uint64_t); idx++)
            {
                if (ptr[idx])
                    return false;
            }
            return true;
        }

        void zero() { _data.fill(0); }

        virtual void Randomize() { randombytes(data(), SIZE); }

        typename std::array<uint8_t, SIZE>::iterator begin() { return _data.begin(); }

        typename std::array<uint8_t, SIZE>::iterator end() { return _data.end(); }

        typename std::array<uint8_t, SIZE>::const_iterator begin() const { return _data.cbegin(); }

        typename std::array<uint8_t, SIZE>::const_iterator end() const { return _data.cend(); }

        bool from_string(std::string_view b)
        {
            if (b.size() != sz)
            {
                // log::error(logcat, "Error: buffer size mismatch in aligned buffer!");
                return false;
            }

            std::memcpy(_data.data(), b.data(), b.size());
            return true;
        }

        std::string bt_encode() const
        {
            return oxenc::bt_serialize(_data);
            // return {reinterpret_cast<const char*>(data()), sz};
        }

        bool bt_decode(std::string buf)
        {
            oxenc::bt_deserialize(buf, _data);
            return true;
        }

        std::string_view to_view() const { return {reinterpret_cast<const char*>(data()), sz}; }

        std::string to_string() const { return ToHex(); }

        std::string ToHex() const { return oxenc::to_hex(begin(), end()); }

        std::string ShortHex() const { return oxenc::to_hex(begin(), begin() + 4); }

        bool FromHex(std::string_view str)
        {
            if (str.size() != 2 * size() || !oxenc::is_hex(str))
                return false;
            oxenc::from_hex(str.begin(), str.end(), begin());
            return true;
        }

        static constexpr bool to_string_formattable = true;

      private:
        std::array<uint8_t, SIZE> _data;
    };

    template <typename T>
    concept bt_type = std::is_base_of_v<oxenc::bt_list_consumer, T>;

    template <bt_type T>
    struct bt_printer
    {
        log::CategoryLogger logcat = log::Cat("bt-printer");

        T _bt;

        bool _read(std::string& entry, T& btc)
        {
            if (btc.is_string())
            {
                entry += "string, value='{}']\n"_format(btc.consume_string_view());
            }
            else if (btc.is_unsigned_integer())
            {
                entry += "uint, value='{}']\n"_format(btc.template consume_integer<uint64_t>());
            }
            else if (btc.is_negative_integer())
            {
                entry += "int, value='-{}']\n"_format(btc.template consume_integer<int64_t>());
            }
            else if (btc.is_integer())
            {
                entry += "int, value='{}']\n"_format(btc.template consume_integer<int64_t>());
            }
            else if (btc.is_list())
            {
                {
                    auto sublist = btc.consume_list_consumer();
                    entry += "bt-list, contents=[\n";
                    _read_list(entry, sublist);
                }
            }
            else if (btc.is_dict())
            {
                {
                    auto subdict = btc.consume_dict_consumer();
                    entry += "dict, contents=[ ...\n";
                    _read_dict(entry, subdict);
                }
            }
            else
            {
                entry += "UNKNOWN... early end to btc contents ]\n";
                btc.finish();
                return false;
            }
            return true;
        }

        void _read_list(std::string& entry, oxenc::bt_list_consumer& btlc)
        {
            while (not btlc.is_finished())
            {
                entry += "\tentry: [type="s;
                if (not _read(entry, btlc))
                    return;
            }
        }

        void _read_dict(std::string& entry, oxenc::bt_dict_consumer& btdc)
        {
            while (not btdc.is_finished())
            {
                entry += "\tkey: {}, entry: [type="_format(btdc.key());
                if (not _read(entry, btdc))
                    return;
            }

            entry += "\t...end of dict contents ]\n";
        }

      public:
        bt_printer(std::string_view data)
        {
            try
            {
                if (data.starts_with('l'))
                    _bt = oxenc::bt_list_consumer{data};
                else if (data.starts_with('d'))
                    _bt = oxenc::bt_dict_consumer{data};
                else
                    throw std::invalid_argument{"bt_printer must be given bt list or dict!"};
            }
            catch (const std::exception& e)
            {
                log::critical(logcat, "bt_printer exception: {}", e.what());
            }
        }

        std::string to_string() const
        {
            std::string ret{};

            if constexpr (std::is_same_v<T, oxenc::bt_list_consumer>)
            {
                ret += "\nbt-list contents[ \n";
                _read_list(_bt);
            }
            else
            {
                ret += "\nbt-dict contents[ \n";
                _read_dict(_bt);
            }
            ret += "] ";
            return ret;
        }
        static constexpr bool to_string_formattable = true;
    };

}  // namespace llarp

namespace std
{
    template <size_t sz>
    struct hash<llarp::AlignedBuffer<sz>>
    {
        std::size_t operator()(const llarp::AlignedBuffer<sz>& buf) const noexcept
        {
            if constexpr (alignof(llarp::AlignedBuffer<sz>) >= sizeof(size_t))
                return *reinterpret_cast<const size_t*>(buf.data());
            else
            {
                std::size_t h{};
                std::memcpy(&h, buf.data(), sizeof(h));
                return h;
            }
        }
    };
}  // namespace std
