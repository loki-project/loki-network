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
#include <llarp/net/net.hpp>
#include <llarp/net/net_int.hpp>
#include <llarp/net/traffic_policy.hpp>
#include <llarp/router_contact.hpp>
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

        std::optional<fs::path> rc_file;

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

    struct NetworkConfig
    {
        bool enable_profiling;
        bool save_profiles;
        std::set<RouterID> strict_connect;

        std::optional<fs::path> keyfile;

        std::optional<int> hops;
        std::optional<int> paths;

        bool enable_ipv6{false};
        bool allow_exit{false};
        bool is_reachable{false};
        bool init_tun{true};

        std::set<RouterID> snode_blacklist;

        // Used by RemoteHandler to provide auth tokens for remote exits
        std::unordered_map<NetworkAddress, std::string> exit_auths;
        std::unordered_map<std::string, std::string> ons_exit_auths;

        /*   Auth specific config   */
        auth::AuthType auth_type = auth::AuthType::NONE;
        auth::AuthFileType auth_file_type = auth::AuthFileType::HASHES;

        std::optional<std::string> auth_endpoint;
        std::optional<std::string> auth_method;

        std::unordered_set<NetworkAddress> auth_whitelist;

        std::unordered_set<std::string> auth_static_tokens;

        std::set<fs::path> auth_files;

        std::vector<llarp::dns::SRVData> srv_records;

        std::optional<net::TrafficPolicy> traffic_policy;

        std::optional<std::chrono::milliseconds> path_alignment_timeout;

        /* TESTNET: Under modification */

        // Contents of this file are read directly into ::_reserved_local_addrs
        std::optional<fs::path> addr_map_persist_file;

        // the only member that refers to an actual interface
        std::optional<std::string> _if_name;

        // used for in6_ifreq
        net::if_info _if_info;

        // If _local_ip_range is set, the following two optionals are also set

        // config mapped as "if-addr"
        std::optional<IPRange> _local_ip_range;
        std::optional<oxen::quic::Address> _local_addr;
        std::optional<ip_v> _local_base_ip;

        std::optional<IPRange> _base_ipv6_range = std::nullopt;

        // Remote exit or hidden service addresses mapped to fixed local IP addresses
        // TODO:
        //  - load directly into TunEndpoint mapping
        //      - when a session is created, check mapping when assigning IP's
        std::unordered_map<NetworkAddress, ip_v> _reserved_local_ips;

        // Remote client exit addresses mapped to local IP ranges
        std::unordered_map<NetworkAddress, IPRange> _exit_ranges;

        // Remote client ONS exit addresses mapped to local IP ranges pending ONS address resolution
        std::unordered_map<std::string, IPRange> _ons_ranges;

        // Used when in exit mode; pass down to LocalEndpoint
        std::set<IPRange> _routed_ranges;

        bool enable_route_poker;
        bool blackhole_routes;

        void define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params);
    };

    struct DnsConfig
    {
        bool l3_intercept;

        std::vector<fs::path> hostfiles;

        /* TESTNET: Under modification */
        std::vector<oxen::quic::Address> _upstream_dns;
        oxen::quic::Address _default_dns{"9.9.9.10", DEFAULT_DNS_PORT};
        std::optional<oxen::quic::Address> _query_bind;
        std::vector<oxen::quic::Address> _bind_addrs;

        // Deprecated
        // std::vector<SockAddr_deprecated> upstream_dns;
        // std::optional<SockAddr_deprecated> query_bind;
        // std::vector<SockAddr_deprecated> bind_addr;
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

        bool only_user_port = false;
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
