#pragma once

#include "json_binary_proxy.hpp"

#include <llarp/address/ip_range.hpp>
#include <llarp/util/logging.hpp>

#include <nlohmann/json_fwd.hpp>

namespace llarp
{
    void to_json(nlohmann::json& j, const IPRange& ipr);
    void from_json(const nlohmann::json& j, IPRange& ipr);
}  // namespace llarp

namespace nlohmann
{
    // Specializations of binary types for deserialization; when receiving these from json we expect
    // them encoded in hex or base64.  These may *not* be used for serialization, and will throw if
    // so invoked; for serialization you need to use RPC_COMMAND::response_hex (or _b64) instead.
    template <typename T>
    struct adl_serializer<T, std::enable_if_t<llarp::rpc::json_is_binary<T>>>
    {
        static_assert(std::is_trivially_copyable_v<T> && std::has_unique_object_representations_v<T>);

        static void to_json(json&, const T&)
        {
            throw std::logic_error{"Internal error: binary types are not directly serializable"};
        }
        static void from_json(const json& j, T& val)
        {
            llarp::rpc::load_binary_parameter(j.get<std::string_view>(), false /*no raw*/, val);
        }
    };

}  // namespace nlohmann
