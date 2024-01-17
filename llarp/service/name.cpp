#include "name.hpp"

#include <llarp/crypto/crypto.hpp>

namespace llarp::service
{
    std::optional<Address> EncryptedName::Decrypt(std::string_view name) const
    {
        if (ciphertext.empty())
            return std::nullopt;
        const auto maybe = crypto::maybe_decrypt_name(ciphertext, nonce, name);
        if (maybe.has_value())
            return Address{*maybe};
        return std::nullopt;
    }
}  // namespace llarp::service
