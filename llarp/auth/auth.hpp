#pragma once

#include "types.hpp"

#include <llarp/address/address.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/router_id.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/util/concept.hpp>
#include <llarp/util/str.hpp>
#include <llarp/util/thread/threading.hpp>

#include <oxenmq/oxenmq.h>

#include <functional>
#include <optional>
#include <string>
#include <unordered_set>

namespace llarp
{
    struct Router;
}  // namespace llarp

namespace llarp::auth
{
    struct AuthPolicy
    {
      protected:
        Router& _router;

      public:
        AuthPolicy(Router& r) : _router{r}
        {}
        virtual ~AuthPolicy() = default;

        virtual std::weak_ptr<AuthPolicy> get_weak() = 0;

        virtual std::shared_ptr<AuthPolicy> get_self() = 0;

        const Router& router() const
        {
            return _router;
        }

        Router& router()
        {
            return _router;
        }
    };

    struct SessionAuthPolicy final : public AuthPolicy, public std::enable_shared_from_this<SessionAuthPolicy>
    {
      private:
        SecretKey _session_key;
        NetworkAddress _remote;
        const bool _is_snode_service{false};
        const bool _is_exit_service{false};

      public:
        SessionAuthPolicy(Router& r, RouterID& remote, bool _snode_service, bool _is_exit = false);

        bool load_identity_from_file(const char* fname);

        std::optional<std::string_view> fetch_auth_token();

        const SecretKey& session_key() const
        {
            return _session_key;
        }

        bool is_snode_service() const
        {
            return _is_snode_service;
        }

        bool is_exit_service() const
        {
            return _is_exit_service;
        }

        std::weak_ptr<AuthPolicy> get_weak() override
        {
            return weak_from_this();
        }

        std::shared_ptr<AuthPolicy> get_self() override
        {
            return shared_from_this();
        }
    };

    struct FileAuthPolicy final : public AuthPolicy, public std::enable_shared_from_this<FileAuthPolicy>
    {
        FileAuthPolicy(Router& r, std::set<fs::path> files, AuthFileType filetype)
            : AuthPolicy{r}, _files{std::move(files)}, _type{filetype}
        {}

        std::weak_ptr<AuthPolicy> get_weak() override
        {
            return weak_from_this();
        }

        std::shared_ptr<AuthPolicy> get_self() override
        {
            return shared_from_this();
        }

      private:
        const std::set<fs::path> _files;
        const AuthFileType _type;
        mutable util::Mutex _m;
        std::unordered_set<service::SessionTag> _pending;
        /// returns an auth result for a auth info challange, opens every file until it finds a
        /// token matching it this is expected to be done in the IO thread
        AuthResult check_files(const AuthInfo& info) const;

        bool check_passwd(std::string hash, std::string challenge) const;
    };

    struct RPCAuthPolicy final : public AuthPolicy, public std::enable_shared_from_this<RPCAuthPolicy>
    {
        explicit RPCAuthPolicy(
            Router& r,
            std::string url,
            std::string method,
            std::unordered_set<NetworkAddress> addr_whitelist,
            std::unordered_set<std::string> token_whitelist,
            std::shared_ptr<oxenmq::OxenMQ> lmq);

        ~RPCAuthPolicy() override = default;

        std::weak_ptr<AuthPolicy> get_weak() override
        {
            return weak_from_this();
        }

        std::shared_ptr<AuthPolicy> get_self() override
        {
            return shared_from_this();
        }

        void start();

      private:
        const std::string _endpoint;
        const std::string _method;
        const std::unordered_set<NetworkAddress> _whitelist;
        const std::unordered_set<std::string> _static_tokens;

        std::shared_ptr<oxenmq::OxenMQ> _omq;
        std::optional<oxenmq::ConnectionID> _omq_conn;
        std::unordered_set<service::SessionTag> _pending_sessions;
    };

    template <typename auth_t>
    concept CONCEPT_COMPAT AuthPolicyType = std::is_base_of_v<AuthPolicy, auth_t>;

    template <AuthPolicyType auth_t, typename... Opt>
    inline static std::shared_ptr<auth_t> make_auth_policy(Router& r, Opt&&... opts)
    {
        return std::make_shared<auth_t>(r, std::forward<Opt>(opts)...);
    }

    /// maybe get auth result from string
    inline std::optional<AuthCode> parse_auth_code(std::string data)
    {
        std::unordered_map<std::string, AuthCode> values = {
            {"OKAY", AuthCode::ACCEPTED},
            {"REJECT", AuthCode::REJECTED},
            {"PAYME", AuthCode::PAYMENT_REQUIRED},
            {"LIMITED", AuthCode::RATE_LIMIT}};
        auto itr = values.find(data);
        if (itr == values.end())
            return std::nullopt;
        return itr->second;
    }

    /// get an auth type from a string
    /// throws std::invalid_argument if arg is invalid
    inline AuthType parse_auth_type(std::string data)
    {
        std::unordered_map<std::string, AuthType> values = {
            {"file", AuthType::FILE},
            {"lmq", AuthType::OMQ},
            {"whitelist", AuthType::WHITELIST},
            {"none", AuthType::NONE}};
        const auto itr = values.find(data);
        if (itr == values.end())
            throw std::invalid_argument("no such auth type: " + data);
        return itr->second;
    }

    /// get an auth file type from a string
    /// throws std::invalid_argument if arg is invalid
    inline AuthFileType parse_auth_file_type(std::string data)
    {
        std::unordered_map<std::string, AuthFileType> values = {
            {"plain", AuthFileType::PLAIN},
            {"plaintext", AuthFileType::PLAIN},
            {"hashed", AuthFileType::HASHES},
            {"hashes", AuthFileType::HASHES},
            {"hash", AuthFileType::HASHES}};
        const auto itr = values.find(data);
        if (itr == values.end())
            throw std::invalid_argument("no such auth file type: " + data);
#ifndef HAVE_CRYPT
        if (itr->second == AuthFileType::HASHES)
            throw std::invalid_argument("unsupported auth file type: " + data);
#endif
        return itr->second;
    }
}  // namespace llarp::auth
