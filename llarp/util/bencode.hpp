#pragma once

#include "bencode.h"
#include "buffer.hpp"
#include "file.hpp"
#include "mem.hpp"

#include <llarp/util/logging.hpp>

#include <oxenc/bt.h>

#include <set>
#include <type_traits>
#include <vector>

namespace llarp
{
    static auto ben_cat = log::Cat("stupid.bencode");

    template <typename T>
    T decode_key(oxenc::bt_dict_consumer& btdp, const char* key)
    {
        return btdp.require<T>(key);
    }

    template <typename List_t>
    bool BEncodeReadList(List_t& result, llarp_buffer_t* buf);

    template <typename Obj_t>
    bool BEncodeWriteDictString(const char* k, const Obj_t& str, llarp_buffer_t* buf)
    {
        return bencode_write_bytestring(buf, k, 1) && bencode_write_bytestring(buf, str.data(), str.size());
    }

    template <typename Obj_t>
    bool BEncodeWriteDictEntry(const char* k, const Obj_t& o, llarp_buffer_t* buf)
    {
        if (auto b = bencode_write_bytestring(buf, k, 1); not b)
            return false;
        auto bte = o.bt_encode();
        buf->write(bte.begin(), bte.end());
        return true;
    }

    template <typename Int_t>
    bool BEncodeWriteDictInt(const char* k, const Int_t& i, llarp_buffer_t* buf)
    {
        if (!bencode_write_bytestring(buf, k, 1))
            return false;
        if constexpr (std::is_enum_v<Int_t>)
            return bencode_write_uint64(buf, static_cast<std::underlying_type_t<Int_t>>(i));
        else
            return bencode_write_uint64(buf, i);
    }

    template <typename List_t>
    bool BEncodeMaybeReadDictList(
        const char* k, List_t& item, bool& read, const llarp_buffer_t& key, llarp_buffer_t* buf)
    {
        if (key.startswith(k))
        {
            if (!BEncodeReadList(item, buf))
            {
                return false;
            }
            read = true;
        }
        return true;
    }

    template <typename Item_t>
    bool BEncodeMaybeReadDictEntry(
        const char* k, Item_t& item, bool& read, const llarp_buffer_t& key, llarp_buffer_t* buf)
    {
        if (key.startswith(k))
        {
            if (!item.BDecode(buf))
            {
                llarp::LogWarn("failed to decode key ", k, " for entry in dict");

                return false;
            }
            read = true;
        }
        return true;
    }

    template <typename Int_t>
    bool BEncodeMaybeReadDictInt(const char* k, Int_t& i, bool& read, const llarp_buffer_t& key, llarp_buffer_t* buf)
    {
        if (key.startswith(k))
        {
            uint64_t read_i;
            if (!bencode_read_integer(buf, &read_i))
            {
                llarp::LogWarn("failed to decode key ", k, " for integer in dict");
                return false;
            }

            i = static_cast<Int_t>(read_i);
            read = true;
        }
        return true;
    }

    /// If the key matches, reads in the version and ensures that it equals the
    /// expected version
    template <typename Item_t>
    bool BEncodeMaybeVerifyVersion(
        const char* k, Item_t& item, uint64_t expect, bool& read, const llarp_buffer_t& key, llarp_buffer_t* buf)
    {
        if (key.startswith(k))
        {
            if (!bencode_read_integer(buf, &item))
                return false;
            read = item == expect;
        }
        return true;
    }

    template <typename List_t>
    bool BEncodeWriteDictBEncodeList(const char* k, const List_t& l, llarp_buffer_t* buf)
    {
        oxenc::bt_dict_producer btdp;

        {
            auto sublist = btdp.append_list(k);

            for (const auto& item : l)
            {
                sublist.append(l.bt_encode());
            }
        }

        auto view = btdp.view();
        buf->write(view.begin(), view.end());

        return true;
    }

    template <typename Array>
    bool BEncodeWriteDictArray(const char* k, const Array& array, llarp_buffer_t* buf)
    {
        if (!bencode_write_bytestring(buf, k, 1))
            return false;
        if (!bencode_start_list(buf))
            return false;

        for (size_t idx = 0; idx < array.size(); ++idx)
            if (!array[idx].bt_encode(buf))
                return false;
        return bencode_end(buf);
    }

    template <typename Iter>
    bool BEncodeWriteList(Iter itr, Iter end, llarp_buffer_t* buf)
    {
        oxenc::bt_list_producer btlp;

        try
        {
            while (itr != end)
                btlp.append(itr->bt_encode());
        }
        catch (...)
        {
            log::critical(ben_cat, "Stupid bencode.hpp shim code failed.");
        }

        auto view = btlp.view();
        if (auto b = buf->write(view.begin(), view.end()); not b)
            return false;

        return true;
    }

    template <typename Sink>
    bool bencode_read_dict(Sink&& sink, llarp_buffer_t* buffer)
    {
        if (buffer->size_left() < 2)  // minimum case is 'de'
            return false;
        if (*buffer->cur != 'd')  // ensure is a dictionary
            return false;
        buffer->cur++;
        while (buffer->size_left() && *buffer->cur != 'e')
        {
            llarp_buffer_t strbuf;  // temporary buffer for current element
            if (bencode_read_string(buffer, &strbuf))
            {
                if (!sink(buffer, &strbuf))  // check for early abort
                    return false;
            }
            else
                return false;
        }

        if (*buffer->cur != 'e')
        {
            llarp::LogWarn("reading dict not ending on 'e'");
            // make sure we're at dictionary end
            return false;
        }
        buffer->cur++;
        return sink(buffer, nullptr);
    }

    template <typename Sink>
    bool bencode_decode_dict(Sink&& sink, llarp_buffer_t* buff)
    {
        return bencode_read_dict(
            [&](llarp_buffer_t* buffer, llarp_buffer_t* key) {
                if (key == nullptr)
                    return true;
                if (sink.decode_key(*key, buffer))
                    return true;
                llarp::LogWarn("undefined key '", *key->cur, "' for entry in dict");

                return false;
            },
            buff);
    }

    template <typename Sink>
    bool bencode_read_list(Sink&& sink, llarp_buffer_t* buffer)
    {
        if (buffer->size_left() < 2)  // minimum case is 'le'
            return false;
        if (*buffer->cur != 'l')  // ensure is a list
        {
            llarp::LogWarn("bencode::bencode_read_list - expecting list got ", *buffer->cur);
            return false;
        }

        buffer->cur++;
        while (buffer->size_left() && *buffer->cur != 'e')
        {
            if (!sink(buffer, true))  // check for early abort
                return false;
        }
        if (*buffer->cur != 'e')  // make sure we're at a list end
            return false;
        buffer->cur++;
        return sink(buffer, false);
    }

    template <typename Array>
    bool BEncodeReadArray(Array& array, llarp_buffer_t* buf)
    {
        size_t idx = 0;
        return bencode_read_list(
            [&array, &idx](llarp_buffer_t* buffer, bool has) {
                if (has)
                {
                    if (idx >= array.size())
                        return false;
                    if (!array[idx++].BDecode(buffer))
                        return false;
                }
                return true;
            },
            buf);
    }
    template <typename List_t>
    bool BEncodeReadList(List_t& result, llarp_buffer_t* buf)
    {
        return bencode_read_list(
            [&result](llarp_buffer_t* buffer, bool has) {
                if (has)
                {
                    if (!result.emplace(result.end())->BDecode(buffer))
                    {
                        return false;
                    }
                }
                return true;
            },
            buf);
    }

    /// read a std::set of decodable entities and deny duplicates
    template <typename Set_t>
    bool BEncodeReadSet(Set_t& set, llarp_buffer_t* buffer)
    {
        return bencode_read_list(
            [&set](llarp_buffer_t* buf, bool more) {
                if (more)
                {
                    typename Set_t::value_type item;
                    if (not item.BDecode(buf))
                        return false;
                    // deny duplicates
                    return set.emplace(item).second;
                }
                return true;
            },
            buffer);
    }

    template <typename List_t>
    bool BEncodeWriteDictList(const char* k, List_t& list, llarp_buffer_t* buf)
    {
        return bencode_write_bytestring(buf, k, 1) && BEncodeWriteList(list.begin(), list.end(), buf);
    }

    template <size_t bufsz, typename T>
    void Dump(const T& val)
    {
        std::array<uint8_t, bufsz> tmp;
        llarp_buffer_t buf(tmp);

        auto bte = val.bt_encode();

        if (auto b = buf.write(bte.begin(), bte.end()); b)
            llarp::DumpBuffer<decltype(buf), 128>(buf);
    }

    /// read entire file and decode its contents into t
    template <typename T>
    bool BDecodeReadFile(const fs::path fpath, T& t)
    {
        std::string content;
        try
        {
            content = util::file_to_string(fpath);
        }
        catch (const std::exception&)
        {
            return false;
        }
        llarp_buffer_t buf(content);
        return t.BDecode(&buf);
    }

    /// bencode and write to file
    template <typename T, size_t bufsz>
    bool BEncodeWriteFile(const fs::path fpath, const T& t)
    {
        std::string tmp(bufsz, 0);
        llarp_buffer_t buf(tmp);

        auto bte = t.bt_encode();
        buf.write(bte.begin(), bte.end());

        tmp.resize(buf.cur - buf.base);
        try
        {
            util::buffer_to_file(fpath, tmp);
        }
        catch (const std::exception& e)
        {
            return false;
        }
        return true;
    }

    /// seek for an int in a dict with a key k used for version
    /// set v to parsed value if found
    /// this call rewinds the buffer unconditionally before return
    /// returns false only if there was
    template <typename Int_t>
    bool BEncodeSeekDictVersion(Int_t& v, llarp_buffer_t* buf, const uint8_t k)
    {
        const auto ret = bencode_read_dict(
            [&v, k](llarp_buffer_t* buffer, llarp_buffer_t* key) -> bool {
                if (key == nullptr)
                    return true;
                if (key->sz == 1 && *key->cur == k)
                {
                    return bencode_read_integer(buffer, &v);
                }
                return bencode_discard(buffer);
            },
            buf);
        // rewind
        buf->cur = buf->base;
        return ret;
    }

}  // namespace llarp
