#pragma once

#include "types.hpp"

#include <llarp/crypto/types.hpp>
#include <llarp/service/address.hpp>
#include <llarp/service/protocol.hpp>
#include <llarp/service/tag.hpp>
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

    namespace service
    {
        struct Endpoint;
    }
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

        /// asynchronously determine if we accept new convotag from remote service, call hook with
        /// result later
        virtual void authenticate_async(
            std::shared_ptr<service::ProtocolMessage> msg, std::function<void(std::string, bool)> hook) = 0;

        /// return true if we are asynchronously processing authentication on this sessiontag
        virtual bool auth_async_pending(service::SessionTag tag) const = 0;
    };

    struct SessionAuthPolicy final : public AuthPolicy, public std::enable_shared_from_this<SessionAuthPolicy>
    {
      protected:
        SecretKey _session_key;
        const bool _is_snode_service{false};
        const bool _is_exit_service{false};

      public:
        SessionAuthPolicy(Router& r, const SecretKey& sk, bool _snode_service, bool _is_exit = false);

        bool load_identity_from_file(const char* fname);

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

        void authenticate_async(
            std::shared_ptr<service::ProtocolMessage> msg, std::function<void(std::string, bool)> hook) override;

        bool auth_async_pending(service::SessionTag tag) const override;
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

        void authenticate_async(
            std::shared_ptr<service::ProtocolMessage> msg, std::function<void(std::string, bool)> hook) override;

        bool auth_async_pending(service::SessionTag tag) const override;

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
            std::unordered_set<llarp::service::Address> addr_whitelist,
            std::unordered_set<std::string> token_whitelist,
            std::shared_ptr<oxenmq::OxenMQ> lmq,
            std::shared_ptr<service::Endpoint> endpoint);

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

        void authenticate_async(
            std::shared_ptr<llarp::service::ProtocolMessage> msg, std::function<void(std::string, bool)> hook) override;

        bool auth_async_pending(service::SessionTag tag) const override;

      private:
        const std::string _url;
        const std::string _method;
        const std::unordered_set<llarp::service::Address> _whitelist;
        const std::unordered_set<std::string> _static_tokens;

        std::shared_ptr<oxenmq::OxenMQ> _omq;
        std::shared_ptr<service::Endpoint> _ep;
        std::optional<oxenmq::ConnectionID> _omq_conn;
        std::unordered_set<service::SessionTag> _pending_sessions;
    };

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

    template <typename... Opt, typename Auth_t, std::enable_if_t<std::is_base_of_v<AuthPolicy, Auth_t>, int> = 0>
    static std::shared_ptr<AuthPolicy> make_auth_policy(Router& r, Opt&&... opts)
    {
        return std::make_shared<Auth_t>(r, std::forward<Opt>(opts)...);
    }

}  // namespace llarp::auth
