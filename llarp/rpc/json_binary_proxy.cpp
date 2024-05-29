#include "json_binary_proxy.hpp"

#include <oxenc/base64.h>
#include <oxenc/hex.h>

using namespace std::literals;

namespace llarp::rpc
{

    void load_binary_parameter_impl(std::string_view bytes, size_t raw_size, bool allow_raw, uint8_t* val_data)
    {
        if (allow_raw && bytes.size() == raw_size)
        {
            std::memcpy(val_data, bytes.data(), bytes.size());
            return;
        }
        else if (bytes.size() == raw_size * 2)
        {
            if (oxenc::is_hex(bytes))
            {
                oxenc::from_hex(bytes.begin(), bytes.end(), val_data);
                return;
            }
        }
        else
        {
            const size_t b64_padded = (raw_size + 2) / 3 * 4;
            const size_t b64_padding = raw_size % 3 == 1 ? 2 : raw_size % 3 == 2 ? 1 : 0;
            const size_t b64_unpadded = b64_padded - b64_padding;
            const std::string_view b64_padding_string = b64_padding == 2 ? "=="sv : b64_padding == 1 ? "="sv : ""sv;
            if (bytes.size() == b64_unpadded
                || (b64_padding > 0 && bytes.size() == b64_padded && bytes.substr(b64_unpadded) == b64_padding_string))
            {
                if (oxenc::is_base64(bytes))
                {
                    oxenc::from_base64(bytes.begin(), bytes.end(), val_data);
                    return;
                }
            }
        }

        throw std::runtime_error{"Invalid binary value: unexpected size and/or encoding"};
    }

    nlohmann::json& json_binary_proxy::operator=(std::string_view binary_data)
    {
        switch (format)
        {
            case fmt::bt:
                return e = binary_data;
            case fmt::hex:
                return e = oxenc::to_hex(binary_data);
            case fmt::base64:
                return e = oxenc::to_base64(binary_data);
        }
        throw std::runtime_error{"Internal error: invalid binary encoding"};
    }

}  // namespace llarp::rpc
