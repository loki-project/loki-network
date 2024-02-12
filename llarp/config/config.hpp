#pragma once

#include "definition.hpp"
#include "ini.hpp"

#include <llarp/address/address.hpp>
#include <llarp/address/ip_range.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/bootstrap.hpp>
#include <llarp/constants/files.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/dns/srv_data.hpp>
#include <llarp/net/ip_address.hpp>
#include <llarp/net/ip_range_map.hpp>
#include <llarp/net/net.hpp>
#include <llarp/net/net_int.hpp>
#include <llarp/net/traffic_policy.hpp>
#include <llarp/router_contact.hpp>
#include <llarp/service/address.hpp>
#include <llarp/util/fs.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/str.hpp>

#include <oxenmq/address.h>

#include <chrono>
#include <cstdlib>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace llarp
{
    using SectionValues = llarp::ConfigParser::SectionValues;
    using ConfigMap = llarp::ConfigParser::ConfigMap;

    inline constexpr uint16_t DEFAULT_LISTEN_PORT{1090};
    inline constexpr uint16_t DEFAULT_DNS_PORT{53};
    inline constexpr int CLIENT_ROUTER_CONNECTIONS = 4;

    // TODO: don't use these maps. they're sloppy and difficult to follow
    /// Small struct to gather all parameters needed for config generation to reduce the number of
    /// parameters that need to be passed around.
    struct ConfigGenParameters
    {
        ConfigGenParameters() = default;
        virtual ~ConfigGenParameters() = default;

        ConfigGenParameters(const ConfigGenParameters&) = delete;
        ConfigGenParameters(ConfigGenParameters&&) = delete;

        bool is_relay = false;
        fs::path default_data_dir;

        /// get network platform (virtual for unit test mocks)
        virtual const llarp::net::Platform* net_ptr() const = 0;
    };

    struct RouterConfig
    {
        int client_router_connections{CLIENT_ROUTER_CONNECTIONS};

        std::string net_id;

        fs::path data_dir;

        bool block_bogons = false;

        int worker_threads = -1;
        int net_threads = -1;

        size_t job_que_size = 0;

        std::string rc_file;
        std::string enckey_file;
        std::string idkey_file;
        std::string transkey_file;

        bool is_relay = false;

        std::optional<std::string> public_ip;
        std::optional<uint16_t> public_port;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    /// config for path hop selection
    struct PeerSelectionConfig
    {
        /// in our hops what netmask will we use for unique ips for hops
        /// i.e. 32 for every hop unique ip, 24 unique /24 per hop, etc
        uint8_t unique_hop_netmask;

        /// set of countrys to exclude from path building (2 char country code)
        std::unordered_set<std::string> exclude_countries;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);

        /// return true if this set of router contacts is acceptable against this config
        bool check_rcs(const std::set<RemoteRC>& hops) const;
    };

    /** TODO: unfuck the config in regards to tun mapping vs exit/service mapping
     */
    struct NetworkConfig
    {
        std::optional<bool> enable_profiling;
        bool save_profiles;
        std::set<RouterID> strict_connect;

        std::optional<fs::path> keyfile;

        std::string endpoint_type{"tun"};

        std::optional<int> hops;
        std::optional<int> paths;

        bool allow_exit = false;
        bool is_reachable = false;

        std::set<RouterID> snode_blacklist;

        std::unordered_map<service::Address, auth::AuthInfo> exit_auths;
        std::unordered_map<std::string, auth::AuthInfo> ons_exit_auths;

        auth::AuthType auth_type = auth::AuthType::NONE;
        auth::AuthFileType auth_file_type = auth::AuthFileType::HASHES;
        std::optional<std::string> auth_url;
        std::optional<std::string> auth_method;
        std::unordered_set<service::Address> auth_whitelist;
        std::unordered_set<std::string> auth_static_tokens;
        std::set<fs::path> auth_files;

        std::vector<llarp::dns::SRVData> srv_records;

        std::optional<net::TrafficPolicy> traffic_policy;

        std::optional<llarp_time_t> path_alignment_timeout;

        std::optional<fs::path> addr_map_persist_file;

        /* TESTNET: Under modification */
        std::string _if_name;
        IPRange _if_addr;
        std::optional<IPRange> _base_ipv6_range = std::nullopt;
        std::unordered_map<ClientAddress, oxen::quic::Address> _addr_map;

        std::unordered_map<ClientAddress, IPRange> _range_map;
        std::unordered_map<std::string, IPRange> _ons_range_map;

        std::set<IPRange> _owned_ranges;

        // DEPRECATED
        // IP_range_deprecated if_addr;
        // std::optional<huint128_t> base_ipv6_range = std::nullopt;
        std::unordered_map<huint128_t, service::Address> addr_map;
        net::IPRangeMap<service::Address> range_map;
        net::IPRangeMap<std::string> ons_range_map;
        // std::set<IP_range_deprecated> owned_ranges;
        /*************************************/

        bool enable_route_poker;
        bool blackhole_routes;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    struct DnsConfig
    {
        bool raw;

        std::vector<fs::path> hostfiles;

        /* TESTNET: Under modification */
        std::vector<oxen::quic::Address> _upstream_dns;
        oxen::quic::Address _default_dns{"9.9.9.10", DEFAULT_DNS_PORT};
        std::optional<oxen::quic::Address> _query_bind;
        std::vector<oxen::quic::Address> _bind_addrs;

        // Deprecated
        // std::vector<SockAddr_deprecated> upstream_dns;
        // std::optional<SockAddr_deprecated> query_bind;
        std::vector<SockAddr_deprecated> bind_addr;
        /*************************************/

        std::unordered_multimap<std::string, std::string> extra_opts;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    struct LinksConfig
    {
        // DEPRECATED -- use [Router]:public_addr
        std::optional<std::string> public_addr;
        // DEPRECATED -- use [Router]:public_port
        std::optional<uint16_t> public_port;

        std::optional<oxen::quic::Address> listen_addr;

        bool using_user_value = false;
        bool using_new_api = false;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    // TODO: remove oxenmq from this header
    struct ApiConfig
    {
        bool enable_rpc_server = false;
        std::vector<oxenmq::address> rpc_bind_addrs;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    struct LokidConfig
    {
        fs::path id_keyfile;
        oxenmq::address rpc_addr;
        bool disable_testing = true;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    struct BootstrapConfig
    {
        std::vector<fs::path> files;
        bool seednode;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    struct LoggingConfig
    {
        log::Type type = log::Type::Print;
        log::Level level = log::Level::off;
        std::string file;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    struct Config
    {
        explicit Config(std::optional<fs::path> datadir = std::nullopt);

        virtual ~Config() = default;

        /// create generation params (virtual for unit test mock)
        virtual std::unique_ptr<ConfigGenParameters> make_gen_params() const;

        RouterConfig router;
        NetworkConfig network;
        PeerSelectionConfig paths;
        DnsConfig dns;
        LinksConfig links;
        ApiConfig api;
        LokidConfig lokid;
        BootstrapConfig bootstrap;
        LoggingConfig logging;

        // Initialize config definition
        void init_config(ConfigDefinition& conf, const ConfigGenParameters& params);

        /// Insert config entries for backwards-compatibility (e.g. so that the config system will
        /// tolerate old values that are no longer accepted)
        ///
        /// @param conf is the config to modify
        void add_backcompat_opts(ConfigDefinition& conf);

        // Load a config from the given file if the config file is not provided LoadDefault is
        // called
        bool load(std::optional<fs::path> fname = std::nullopt, bool isRelay = false);

        // Load a config from a string of ini, same effects as Config::Load
        bool load_string(std::string_view ini, bool isRelay = false);

        std::string generate_client_config_base();

        std::string generate_router_config_base();

        void save();

        void override(std::string section, std::string key, std::string value);

        void add_default(std::string section, std::string key, std::string value);

        /// create a config with the default parameters for an embedded lokinet
        static std::shared_ptr<Config> make_embedded_config();

       private:
        /// Load (initialize) a default config.
        ///
        /// This delegates to the ConfigDefinition to generate a default config,
        /// as though an empty config were specified.
        ///
        /// If using Config without the intention of loading from file (or string), this is
        /// necessary in order to obtain sane defaults.
        ///
        /// @param isRelay determines whether the config will reflect that of a relay or client
        /// @param dataDir is a path representing a directory to be used as the data dir
        /// @return true on success, false otherwise
        bool load_default_config(bool isRelay);

        bool load_config_data(std::string_view ini, std::optional<fs::path> fname = std::nullopt, bool isRelay = false);

        void load_overrides(ConfigDefinition& conf) const;

        std::vector<std::array<std::string, 3>> additional;
        ConfigParser parser;
        const fs::path data_dir;
    };

    void ensure_config(fs::path dataDir, fs::path confFile, bool overwrite, bool asRouter);

}  // namespace llarp
