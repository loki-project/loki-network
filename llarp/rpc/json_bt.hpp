#pragma once

#include <nlohmann/json.hpp>
#include <oxenc/bt_value.h>

using nlohmann::json;

namespace llarp::rpc
{

    inline oxenc::bt_value json_to_bt(json&& j)
    {
        if (j.is_object())
        {
            oxenc::bt_dict res;
            for (auto& [k, v] : j.items())
            {
                if (v.is_null())
                    continue;  // skip k-v pairs with a null v (for other nulls we fail).
                res[k] = json_to_bt(std::move(v));
            }
            return res;
        }
        if (j.is_array())
        {
            oxenc::bt_list res;
            for (auto& v : j)
                res.push_back(json_to_bt(std::move(v)));
            return res;
        }
        if (j.is_string())
        {
            return std::move(j.get_ref<std::string&>());
        }
        if (j.is_boolean())
            return j.get<bool>() ? 1 : 0;
        if (j.is_number_unsigned())
            return j.get<uint64_t>();
        if (j.is_number_integer())
            return j.get<int64_t>();
        throw std::domain_error{"internal error: encountered some unhandled/invalid type in json-to-bt translation"};
    }

}  // namespace llarp::rpc
