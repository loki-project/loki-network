#pragma once

#include <llarp/constants/link_layer.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/mem.hpp>

#include <stdexcept>
#include <vector>

namespace llarp
{
    /// encrypted buffer base type
    template <size_t bufsz = MAX_LINK_MSG_SIZE>
    struct Encrypted
    {
        Encrypted(Encrypted&& other)
        {
            _sz = std::move(other._sz);
            _buf = std::move(other._buf);
            UpdateBuffer();
        }

        Encrypted(const Encrypted& other) : Encrypted(other.data(), other.size()) { UpdateBuffer(); }

        Encrypted() { Clear(); }

        void Clear()
        {
            _sz = 0;
            UpdateBuffer();
        }

        Encrypted(const uint8_t* buf, size_t sz)
        {
            if (sz <= bufsz)
            {
                _sz = sz;
                if (buf)
                    memcpy(_buf.data(), buf, sz);
                else
                    _buf.zero();
            }
            else
                _sz = 0;
            UpdateBuffer();
        }

        Encrypted(size_t sz) : Encrypted(nullptr, sz) {}

        bool BEncode(llarp_buffer_t* buf) const { return bencode_write_bytestring(buf, data(), _sz); }

        bool operator==(const Encrypted& other) const
        {
            return _sz == other._sz && memcmp(data(), other.data(), _sz) == 0;
        }

        bool operator!=(const Encrypted& other) const { return !(*this == other); }

        Encrypted& operator=(const Encrypted& other) { return Encrypted::operator=(llarp_buffer_t(other)); }

        Encrypted& operator=(const llarp_buffer_t& buf)
        {
            if (buf.sz <= _buf.size())
            {
                _sz = buf.sz;
                memcpy(_buf.data(), buf.base, _sz);
            }
            UpdateBuffer();
            return *this;
        }

        void Fill(uint8_t fill) { std::fill(_buf.begin(), _buf.begin() + _sz, fill); }

        void Randomize()
        {
            if (_sz)
                randombytes(_buf.data(), _sz);
        }

        bool BDecode(llarp_buffer_t* buf)
        {
            llarp_buffer_t strbuf;
            if (!bencode_read_string(buf, &strbuf))
                return false;
            if (strbuf.sz > sizeof(_buf))
                return false;
            _sz = strbuf.sz;
            if (_sz)
                memcpy(_buf.data(), strbuf.base, _sz);
            UpdateBuffer();
            return true;
        }

        std::string to_string() { return {reinterpret_cast<const char*>(data()), size()}; }

        ustring to_ustring() { return {data(), size()}; }

        llarp_buffer_t* Buffer() { return &m_Buffer; }

        size_t size() { return _sz; }

        size_t size() const { return _sz; }

        uint8_t* data() { return _buf.data(); }

        const uint8_t* data() const { return _buf.data(); }

      protected:
        void UpdateBuffer()
        {
            m_Buffer.base = _buf.data();
            m_Buffer.cur = _buf.data();
            m_Buffer.sz = _sz;
        }
        AlignedBuffer<bufsz> _buf;
        size_t _sz;
        llarp_buffer_t m_Buffer;
    };  // namespace llarp
}  // namespace llarp
