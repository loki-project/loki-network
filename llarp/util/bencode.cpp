#include "bencode.hpp"

#include <cinttypes>
#include <cstdlib>

bool bencode_read_integer(struct llarp_buffer_t* buffer, uint64_t* result)
{
    size_t len;
    if (*buffer->cur != 'i')
        return false;

    char numbuf[32];

    buffer->cur++;

    len = buffer->read_until('e', (uint8_t*)numbuf, sizeof(numbuf) - 1);
    if (!len)
    {
        return false;
    }

    buffer->cur++;

    numbuf[len] = '\0';
    if (result)
        *result = std::strtoull(numbuf, nullptr, 10);
    return true;
}

bool bencode_read_string(llarp_buffer_t* buffer, llarp_buffer_t* result)
{
    char numbuf[10];

    size_t len = buffer->read_until(':', (uint8_t*)numbuf, sizeof(numbuf) - 1);
    if (!len)
        return false;

    numbuf[len] = '\0';
    const int num = atoi(numbuf);
    if (num < 0)
    {
        return false;
    }

    const size_t slen = num;

    buffer->cur++;

    len = buffer->size_left();
    if (len < slen)
    {
        return false;
    }
    if (result)
    {
        result->base = buffer->cur;
        result->cur = buffer->cur;
        result->sz = slen;
    }
    buffer->cur += slen;
    return true;
}

bool bencode_write_bytestring(llarp_buffer_t* buff, const void* data, size_t sz)
{
    if (!buff->writef("%zu:", sz))
    {
        return false;
    }
    return buff->write(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data) + sz);
}

bool bencode_write_uint64(llarp_buffer_t* buff, uint64_t i)
{
    if (!buff->writef("i%" PRIu64, i))
    {
        return false;
    }

    static const char letter[1] = {'e'};
    assert(std::distance(std::begin(letter), std::end(letter)) == 1);
    return buff->write(std::begin(letter), std::end(letter));
}

bool bencode_discard(llarp_buffer_t* buf)
{
    if (buf->size_left() == 0)
        return true;
    switch (*buf->cur)
    {
        case 'l':
            return llarp::bencode_read_list(
                [](llarp_buffer_t* buffer, bool more) -> bool {
                    if (more)
                    {
                        return bencode_discard(buffer);
                    }
                    return true;
                },
                buf);
        case 'i':
            return bencode_read_integer(buf, nullptr);
        case 'd':
            return llarp::bencode_read_dict(
                [](llarp_buffer_t* buffer, llarp_buffer_t* key) -> bool {
                    if (key)
                        return bencode_discard(buffer);
                    return true;
                },
                buf);
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return bencode_read_string(buf, nullptr);
        default:
            return false;
    }
}

bool bencode_write_uint64_entry(llarp_buffer_t* buff, const void* name, size_t sz, uint64_t i)
{
    if (!bencode_write_bytestring(buff, name, sz))
        return false;

    return bencode_write_uint64(buff, i);
}

bool bencode_start_list(llarp_buffer_t* buff)
{
    static const char letter[1] = {'l'};
    assert(std::distance(std::begin(letter), std::end(letter)) == 1);
    return buff->write(std::begin(letter), std::end(letter));
}

bool bencode_start_dict(llarp_buffer_t* buff)
{
    static const char letter[1] = {'d'};
    assert(std::distance(std::begin(letter), std::end(letter)) == 1);
    return buff->write(std::begin(letter), std::end(letter));
}

bool bencode_end(llarp_buffer_t* buff)
{
    static const char letter[1] = {'e'};
    assert(std::distance(std::begin(letter), std::end(letter)) == 1);
    return buff->write(std::begin(letter), std::end(letter));
}
