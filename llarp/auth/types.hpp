#pragma once

#include <cstdint>
#include <string>

namespace llarp::auth
{
    /// authentication status code
    enum class AuthCode : uint64_t
    {
        /// explicitly accepted
        ACCEPTED = 0,
        /// explicitly rejected
        REJECTED = 1,
        /// attempt failed
        FAILED = 2,
        /// attempt rate limited
        RATE_LIMIT = 3,
        /// need mo munny
        PAYMENT_REQUIRED = 4
    };

    /// auth result object with code and reason
    struct AuthResult
    {
        AuthCode code;
        std::string reason;
    };

    /// info needed by clients in order to authenticate to a remote endpoint
    struct AuthInfo
    {
        std::string token;
    };

    /// what kind of backend to use for auth
    enum class AuthType
    {
        /// no authentication
        NONE,
        /// manual whitelist
        WHITELIST,
        /// LMQ server
        OMQ,
        /// static file
        FILE,
    };

    /// how to interpret an file for auth
    enum class AuthFileType
    {
        PLAIN,
        HASHES,
    };

}  // namespace llarp::auth
