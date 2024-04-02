#include "abstracthophandler.hpp"

#include <llarp/router/router.hpp>

namespace llarp::path
{
    std::string make_onion_payload(const SymmNonce& nonce, const HopID& path_id, const std::string_view& inner_payload)
    {
        return make_onion_payload(
            nonce,
            path_id,
            ustring_view{reinterpret_cast<const unsigned char*>(inner_payload.data()), inner_payload.size()});
    }

    std::string make_onion_payload(const SymmNonce& nonce, const HopID& path_id, const ustring_view& inner_payload)
    {
        oxenc::bt_dict_producer next_dict;
        next_dict.append("NONCE", nonce.to_view());
        next_dict.append("PATHID", path_id.to_view());
        next_dict.append("PAYLOAD", inner_payload);

        return std::move(next_dict).str();
    }
}  // namespace llarp::path
