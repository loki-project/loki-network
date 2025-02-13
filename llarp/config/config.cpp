#include "config.hpp"

#include "definition.hpp"
#include "ini.hpp"

#include <llarp/constants/platform.hpp>
#include <llarp/constants/version.hpp>
#include <llarp/contact/sns.hpp>
#include <llarp/util/file.hpp>
#include <llarp/util/formattable.hpp>

#include <stdexcept>

namespace llarp
{
    static auto logcat = log::Cat("config");

    static bool check_path_op(std::optional<fs::path>& path)
    {
        if (not path.has_value())
        {
            log::info(logcat, "Path input failed to parse...");
        }
        else if (path->empty())
        {
            log::warning(logcat, "Path contents ({}) empty...", path->c_str());
            path.reset();
        }
        else
        {
            log::debug(logcat, "Valid path parsed ({})", path->c_str());
            return true;
        }

        return false;
    }

    using namespace config;

    namespace
    {
        struct ConfigGenParameters_impl : public ConfigGenParameters
        {
            const llarp::net::Platform* net_ptr() const override { return llarp::net::Platform::Default_ptr(); }
        };
    }  // namespace

    void RouterConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        constexpr Default DefaultJobQueueSize{1024 * 8};
        constexpr Default DefaultWorkerThreads{0};
        constexpr Default DefaultBlockBogons{true};

        conf.define_option<int>("router", "job-queue-size", DefaultJobQueueSize, Hidden, [this](int arg) {
            if (arg < 1024)
                throw std::invalid_argument("job-queue-size must be 1024 or greater");

            job_que_size = arg;
        });

        conf.define_option<std::string>(
            "router",
            "netid",
            Default{llarp::LOKINET_DEFAULT_NETID},
            Comment{
                "Network ID; this is '"s + llarp::LOKINET_DEFAULT_NETID + "' for mainnet, '"s
                    + llarp::LOKINET_TESTNET_NETID + "' for testnet."s,
            },
            [this](std::string arg) {
                if (arg.size() > NETID_SIZE)
                    throw std::invalid_argument{"netid is too long, max length is {}"_format(NETID_SIZE)};

                net_id = std::move(arg);
            });

        conf.define_option<size_t>(
            "router",
            "relay-connections",
            Default{CLIENT_ROUTER_CONNECTIONS},
            ClientOnly,
            Comment{
                "Minimum number of routers lokinet client will attempt to maintain connections to.",
                "If [network]:strict-connect is defined, the number of maintained client <-> router",
                "connections set by [router]:relay-connections will be at MOST the number of pinned edges"},
            [=, this](size_t arg) {
                if (arg < CLIENT_ROUTER_CONNECTIONS)
                    throw std::invalid_argument{
                        "Client relay connections must be >= {}"_format(CLIENT_ROUTER_CONNECTIONS)};

                client_router_connections = arg;
            });

        conf.define_option<int>(
            "router",
            "min-connections",
            Deprecated,
            Comment{
                "Minimum number of routers lokinet will attempt to maintain connections to.",
            },
            [=](int) {
                log::warning(logcat, "Router min-connections is deprecated; use relay-connections for clients");
            });

        conf.define_option<int>(
            "router",
            "max-connections",
            Deprecated,
            Comment{
                "Maximum number (hard limit) of routers lokinet will be connected to at any time.",
            },
            [=](int) {
                log::warning(logcat, "Router max-connections is deprecated; use relay-connections for clients");
            });

        conf.define_option<std::string>("router", "nickname", Deprecated);

        conf.define_option<fs::path>(
            "router",
            "data-dir",
            Default{params.default_data_dir},
            Comment{
                "Optional directory for containing lokinet runtime data. This includes generated",
                "private keys.",
            },
            [this](fs::path arg) {
                if (arg.empty())
                    throw std::invalid_argument("[router]:data-dir is empty");
                if (not fs::exists(arg))
                    throw std::runtime_error{"Specified [router]:data-dir {} does not exist"_format(arg)};

                data_dir = std::move(arg);
            });

        conf.define_option<std::string>(
            "router",
            "public-ip",
            RelayOnly,
            Comment{
                "For complex network configurations where the detected IP is incorrect or "
                "non-public",
                "this setting specifies the public IP at which this router is reachable. When",
                "provided the public-port option must also be specified.",
            },
            [this](std::string arg) { public_ip = std::move(arg); });

        conf.define_option<std::string>("router", "public-address", Hidden, [](std::string) {
            throw std::invalid_argument{
                "[router]:public-address option no longer supported, use [router]:public-ip and "
                "[router]:public-port instead"};
        });

        conf.define_option<uint16_t>(
            "router",
            "public-port",
            RelayOnly,
            Comment{
                "When specifying public-ip=, this specifies the public UDP port at which this "
                "lokinet",
                "router is reachable. Required when public-ip is used.",
            },
            [this](uint16_t arg) {
                if (arg <= 0 || arg > std::numeric_limits<uint16_t>::max())
                    throw std::invalid_argument("public-port must be >= 0 and <= 65536");
                public_port = arg;
            });

        conf.define_option<int>(
            "router",
            "worker-threads",
            DefaultWorkerThreads,
            Comment{
                "The number of threads available for performing cryptographic functions.",
                "The minimum is one thread, but network performance may increase with more.",
                "threads. Should not exceed the number of logical CPU cores.",
                "0 means use the number of logical CPU cores detected at startup.",
            },
            [this](int arg) {
                if (arg < 0)
                    throw std::invalid_argument("worker-threads must be >= 0");

                worker_threads = arg;
            });

        // Hidden option because this isn't something that should ever be turned off occasionally
        // when doing dev/testing work.
        conf.define_option<bool>(
            "router", "block-bogons", DefaultBlockBogons, Hidden, assignment_acceptor(block_bogons));

        constexpr auto relative_to_datadir = "An absolute path is used as-is, otherwise relative to 'data-dir'.";

        conf.define_option<std::string>(
            "router",
            "contact-file",
            RelayOnly,
            [this](std::string arg) {
                if (arg.empty())
                    return;

                rc_file = arg;
                if (check_path_op(rc_file))
                    log::info(logcat, "Relay configured to try RC file path: {}", rc_file->c_str());
                else
                    log::warning(logcat, "Bad input for relay RC file path ({}), using default...", arg);
            },
            Comment{
                "Filename in which to store the router contact file",
                relative_to_datadir,
            });

        conf.define_option<std::string>("router", "encryption-privkey", Deprecated);

        conf.define_option<std::string>("router", "ident-privkey", Deprecated);

        conf.define_option<std::string>("router", "transport-privkey", RelayOnly, Deprecated);

        // Deprecated options:

        // these weren't even ever used!
        conf.define_option<std::string>("router", "max-routers", Deprecated);
        conf.define_option<std::string>("router", "min-routers", Deprecated);

        // TODO: this may have been a synonym for [router]worker-threads
        conf.define_option<std::string>("router", "threads", Deprecated);
        conf.define_option<std::string>("router", "net-threads", Deprecated);

        is_relay = params.is_relay;
    }

    void ExitConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        (void)params;

        conf.define_option<bool>(
            "exit",
            "enable",
            ClientOnly,
            Default{false},
            assignment_acceptor(exit_enabled),
            Comment{
                "Enable exit-node functionality for local lokinet instance.",
            });

        conf.define_option<std::string>(
            "exit",
            "auth",
            ClientOnly,
            MultiValue,
            Comment{
                "Specify an optional authentication token required to use a non-public exit node.",
                "For example:",
                "    auth=myfavouriteexit.loki:abc",
                "uses the authentication code `abc` whenever myfavouriteexit.loki is accessed.",
                "Can be specified multiple times to store codes for different exit nodes.",
            },
            [this](std::string arg) {
                if (arg.empty())
                    throw std::invalid_argument{"Empty argument passed to '[exit]:auth'"};

                const auto pos = arg.find(":");

                if (pos == std::string::npos)
                {
                    throw std::invalid_argument(
                        "[exit]:auth invalid format, expects exit-address.loki:auth-token-goes-here");
                }

                const auto addr = arg.substr(0, pos);
                auto auth = arg.substr(pos + 1);

                if (is_valid_sns(addr))
                {
                    ons_auth_tokens.emplace(std::move(addr), std::move(auth));
                }
                else if (auto exit = NetworkAddress::from_network_addr(addr); exit->is_client())
                {
                    auth_tokens.emplace(std::move(*exit), std::move(auth));
                }
                else
                    throw std::invalid_argument("[exit]:auth invalid exit address");
            });

        conf.define_option<std::string>(
            "exit",
            "policy",
            MultiValue,
            Comment{
                "Specifies the IP traffic accepted by the local exit node traffic policy. If any are",
                "specified then only matched traffic will be allowed and all other traffic will be",
                "dropped. Examples:",
                "    policy=tcp",
                "would allow all TCP/IP packets (regardless of port);",
                "    policy=0x69",
                "would allow IP traffic with IP protocol 0x69;",
                "    policy=udp/53",
                "would allow UDP port 53; and",
                "    policy=tcp/smtp",
                "would allow TCP traffic on the standard smtp port (21).",
            },
            [this](std::string arg) {
                // this will throw on error
                exit_policy.protocols.emplace(arg);
            });

        conf.define_option<std::string>(
            "exit",
            "reserved-range",
            ClientOnly,
            MultiValue,
            Comment{
                "Reserve an ip range to use as an exit broker for a `.loki` address",
                "Specify a `.loki` address and a reserved ip range to use as an exit broker.",
                "Examples:",
                "    reserved-range=whatever.loki",
                "would route all exit traffic through whatever.loki; and",
                "    reserved-range=stuff.loki:100.0.0.0/24",
                "would route the IP range 100.0.0.0/24 through stuff.loki.",
                "This option can be specified multiple times (to map different IP ranges).",
            },
            [this](std::string arg) {
                if (arg.empty())
                    return;

                std::optional<IPRange> range;

                const auto pos = arg.find(":");

                std::string input = (pos == std::string::npos) ? "0.0.0.0/0"s : arg.substr(pos + 1);

                range = IPRange::from_string(std::move(input));

                if (not range.has_value())
                    throw std::invalid_argument("[network]:exit-node invalid ip range for exit provided");

                if (pos != std::string::npos)
                    arg = arg.substr(0, pos);

                if (is_valid_sns(arg))
                    ons_ranges.emplace(std::move(arg), std::move(*range));
                else if (auto maybe_raddr = NetworkAddress::from_network_addr(arg); maybe_raddr)
                    ranges.emplace(std::move(*maybe_raddr), std::move(*range));
                else
                    throw std::invalid_argument{"[network]:exit-node bad address: {}"_format(arg)};
            });

        conf.define_option<std::string>(
            "exit",
            "routed-range",
            MultiValue,
            Comment{
                "Route local exit node traffic through the specified IP range. If omitted, the",
                "default is ALL public ranges.  Can be set to public to indicate that this exit",
                "routes traffic to the public internet.",
                "For example:",
                "    routed-range=10.0.0.0/16",
                "    routed-range=public",
                "to advertise that this exit routes traffic to both the public internet, and to",
                "10.0.x.y addresses.",
                "",
                "Note that this option does not automatically configure network routing; that",
                "must be configured separately on the exit system to handle lokinet traffic.",
            },
            [this](std::string arg) {
                if (auto range = IPRange::from_string(arg))
                    exit_policy.ranges.insert(std::move(*range));
                else
                    throw std::invalid_argument{"Bad IP range passed to routed-range:{}"_format(arg)};
            });
    }

    void NetworkConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        (void)params;

        static constexpr Default ProfilingValueDefault{true};
        static constexpr Default SaveProfilesDefault{true};
        static constexpr Default ReachableDefault{true};
        static constexpr Default HopsDefault{4};
        static constexpr Default PathsDefault{4};
        static constexpr Default IP6RangeDefault{"[fd00::]/16"};

        conf.define_option<bool>(
            "network", "save-profiles", SaveProfilesDefault, Hidden, assignment_acceptor(save_profiles));

        conf.define_option<bool>(
            "network", "profiling", ProfilingValueDefault, Hidden, assignment_acceptor(enable_profiling));

        conf.define_option<std::string>("network", "profiles", Deprecated);

        conf.define_option<std::string>(
            "network",
            "strict-connect",
            ClientOnly,
            MultiValue,
            [this](std::string value) {
                RouterID router;
                if (not router.from_relay_address(value))
                    throw std::invalid_argument{"bad .snode pubkey: {}"_format(value)};
                if (not pinned_edges.insert(router).second)
                    throw std::invalid_argument{"duplicate strict connect .snode: {}"_format(value)};
            },
            Comment{
                "Public keys of routers which will act as pinned first-hops. This may be used to",
                "provide a trusted router (consider that you are not fully anonymous with your",
                "first hop).  This REQUIRES two or more nodes to be specified.",
            });

        conf.define_option<std::string>(
            "network",
            "keyfile",
            ClientOnly,
            [this](std::string arg) {
                if (arg.empty())
                    return;

                keyfile = arg;

                if (check_path_op(keyfile))
                    log::info(logcat, "Client configured to try private key file at path: {}", keyfile->c_str());
                else
                    log::warning(logcat, "Bad input for client private key file ({}); using ephemeral...", arg);
            },
            Comment{
                "The private key to persist address with. If not specified the address will be",
                "ephemerally generated.",
            });

        conf.define_option<std::string>(
            "network",
            "auth-type",
            ClientOnly,
            Comment{
                "Set the endpoint authentication type.",
                "none/whitelist/lmq/file",
            },
            [this](std::string arg) {
                if (arg.empty())
                    return;
                auth_type = parse_auth_type(arg);
            });

        conf.define_option<std::string>(
            "network",
            "omq-auth-endpoint",
            ClientOnly,
            assignment_acceptor(auth_endpoint),
            Comment{
                "OMQ endpoint to talk to for authenticating new sessions",
                "ipc:///var/lib/lokinet/auth.socket",
                "tcp://127.0.0.1:5555",
            });

        conf.define_option<std::string>(
            "network",
            "omq-auth-method",
            ClientOnly,
            Default{"llarp.auth"},
            Comment{
                "OMQ function to call for authenticating new sessions",
                "llarp.auth",
            },
            [this](std::string arg) {
                if (arg.empty())
                    return;
                auth_method = std::move(arg);
            });

        conf.define_option<std::string>(
            "network",
            "auth-whitelist",
            ClientOnly,
            MultiValue,
            Comment{
                "manually add a remote endpoint by .loki address to the access whitelist",
            },
            [this](std::string arg) {
                if (auto addr = NetworkAddress::from_network_addr(arg))
                    auth_whitelist.emplace(std::move(*addr));
                else
                    throw std::invalid_argument{"bad loki address: {}"_format(arg)};
            });

        conf.define_option<fs::path>(
            "network",
            "auth-file",
            ClientOnly,
            MultiValue,
            Comment{
                "Read auth tokens from file to accept endpoint auth",
                "Can be provided multiple times",
            },
            [this](fs::path arg) {
                if (not fs::exists(arg))
                    throw std::invalid_argument{"cannot load auth file {}: file does not exist"_format(arg)};
                auth_files.emplace(std::move(arg));
            });

        conf.define_option<std::string>(
            "network",
            "auth-file-type",
            ClientOnly,
            Comment{
                "How to interpret the contents of an auth file.",
                "Possible values: hashes, plaintext",
            },
            [this](std::string arg) { auth_file_type = parse_auth_file_type(std::move(arg)); });

        conf.define_option<std::string>(
            "network",
            "auth-static",
            ClientOnly,
            MultiValue,
            Comment{
                "Manually add a static auth code to accept for endpoint auth",
                "Can be provided multiple times",
            },
            [this](std::string arg) { auth_static_tokens.emplace(std::move(arg)); });

        conf.define_option<bool>(
            "network",
            "reachable",
            ClientOnly,
            ReachableDefault,
            assignment_acceptor(is_reachable),
            Comment{
                "Determines whether we will pubish our service's ClientContact to the DHT (client default: TRUE)",
            });

        conf.define_option<int>(
            "network",
            "hops",
            HopsDefault,
            Comment{
                "Number of hops in a path. Min 1, max 8.",
            },
            [this](int arg) {
                if (arg < 1 or arg > 8)
                    throw std::invalid_argument("[endpoint]:hops must be >= 1 and <= 8");
                hops = arg;
            });

        conf.define_option<int>(
            "network",
            "paths",
            ClientOnly,
            PathsDefault,
            Comment{
                "Number of paths to maintain at any given time.",
            },
            [this](int arg) {
                if (arg < 3 or arg > 8)
                    throw std::invalid_argument("[endpoint]:paths must be >= 3 and <= 8");
                paths = arg;
            });

        conf.define_option<bool>(
            "network",
            "exit",
            Hidden,
            ClientOnly,
            [this](bool arg) {
                allow_exit = arg;
                log::warning(logcat, "This option is deprecated! Use [exit]:enable instead!");
            },
            Comment{
                "<< DEPRECATED -- use [exit]:enable instead >>\n",
                "Whether or not we should act as an exit node. "
                "Beware that this increases demand",
                "on the server and may pose liability concerns. Enable at your own risk.",
            });

        conf.define_option<std::string>(
            "network",
            "routed-range",
            Hidden,
            MultiValue,
            Comment{
                "<< DEPRECATED -- use [exit]:routed-range instead >>\n",
                "When in exit mode announce one or more IP ranges that this exit node routes",
                "traffic for.  If omitted, the default is all public ranges.  Can be set to",
                "public to indicate that this exit routes traffic to the public internet.",
                "For example:",
                "    routed-range=10.0.0.0/16",
                "    routed-range=public",
                "to advertise that this exit routes traffic to both the public internet, and to",
                "10.0.x.y addresses.",
                "",
                "Note that this option does not automatically configure network routing; that",
                "must be configured separately on the exit system to handle lokinet traffic.",
            },
            [this](std::string arg) {
                if (not traffic_policy)
                    traffic_policy = net::ExitPolicy{};

                if (auto range = IPRange::from_string(arg))
                    traffic_policy->ranges.insert(std::move(*range));
                else
                    throw std::invalid_argument{"Bad IP range passed to routed-range:{}"_format(arg)};
            });

        conf.define_option<std::string>(
            "network",
            "traffic-whitelist",
            Hidden,
            MultiValue,
            Comment{
                "<< DEPRECATED -- use [exit]:policy instead >>\n",
                "Adds an IP traffic type whitelist; can be specified multiple times.  If any are",
                "specified then only matched traffic will be allowed and all other traffic will be",
                "dropped.  Examples:",
                "    traffic-whitelist=tcp",
                "would allow all TCP/IP packets (regardless of port);",
                "    traffic-whitelist=0x69",
                "would allow IP traffic with IP protocol 0x69;",
                "    traffic-whitelist=udp/53",
                "would allow UDP port 53; and",
                "    traffic-whitelist=tcp/smtp",
                "would allow TCP traffic on the standard smtp port (21).",
            },
            [this](std::string arg) {
                if (not traffic_policy)
                    traffic_policy = net::ExitPolicy{};

                log::warning(logcat, "This option is deprecated! Use [exit]:policy instead!");

                // this will throw on error
                traffic_policy->protocols.emplace(arg);
            });

        conf.define_option<std::string>(
            "network",
            "exit-node",
            Hidden,
            ClientOnly,
            MultiValue,
            Comment{
                "<< DEPRECATED -- use [exit]:reserved-range instead >>\n",
                "Specify a `.loki` address and an ip range to use as an exit broker.",
                "Examples:",
                "    exit-node=whatever.loki",
                "would route all exit traffic through whatever.loki; and",
                "    exit-node=stuff.loki:100.0.0.0/24",
                "would route the IP range 100.0.0.0/24 through stuff.loki.",
                "This option can be specified multiple times (to map different IP ranges).",
            },
            [this](std::string arg) {
                if (arg.empty())
                    return;

                log::warning(logcat, "This option is deprecated! Use [exit]:reserved-range instead!");

                std::optional<IPRange> range;

                const auto pos = arg.find(":");

                std::string input = (pos == std::string::npos) ? "0.0.0.0/0"s : arg.substr(pos + 1);

                range = IPRange::from_string(std::move(input));

                if (not range.has_value())
                    throw std::invalid_argument("[network]:exit-node invalid ip range for exit provided");

                if (pos != std::string::npos)
                    arg = arg.substr(0, pos);

                if (is_valid_sns(arg))
                    _ons_ranges.emplace(std::move(arg), std::move(*range));
                else if (auto maybe_raddr = NetworkAddress::from_network_addr(arg); maybe_raddr)
                    _exit_ranges.emplace(std::move(*maybe_raddr), std::move(*range));
                else
                    throw std::invalid_argument{"[network]:exit-node bad address: {}"_format(arg)};
            });

        conf.define_option<std::string>(
            "network",
            "exit-auth",
            ClientOnly,
            Hidden,
            MultiValue,
            Comment{
                "<< DEPRECATED -- use [exit]:auth instead >>\n",
                "Specify an optional authentication code required to use ",
                "a non-public exit node.",
                "For example:",
                "    exit-auth=myfavouriteexit.loki:abc",
                "uses the authentication code `abc` whenever myfavouriteexit.loki is accessed.",
                "Can be specified multiple times to store codes for different exit nodes.",
            },
            [this](std::string arg) {
                if (arg.empty())
                    throw std::invalid_argument{"Empty argument passed to 'exit-auth'"};

                log::warning(logcat, "This option is deprecated! Use [exit]:auth instead!");

                const auto pos = arg.find(":");

                if (pos == std::string::npos)
                {
                    throw std::invalid_argument(
                        "[network]:exit-auth invalid format, expects exit-address.loki:auth-code-goes-here");
                }

                const auto addr = arg.substr(0, pos);
                auto auth = arg.substr(pos + 1);

                if (is_valid_sns(addr))
                {
                    ons_exit_auths.emplace(std::move(addr), std::move(auth));
                }
                else if (auto exit = NetworkAddress::from_network_addr(addr); exit->is_client())
                {
                    exit_auths.emplace(std::move(*exit), std::move(auth));
                }
                else
                    throw std::invalid_argument("[network]:exit-auth invalid exit address");
            });

        conf.define_option<bool>(
            "network",
            "auto-routing",
            ClientOnly,
            Default{true},
            Comment{
                "Enable / disable automatic route configuration.",
                "When this is enabled and an exit is used Lokinet will automatically configure the",
                "operating system routes to route public internet traffic through the exit node.",
                "This is enabled by default, but can be disabled if advanced/manual exit routing",
                "configuration is desired."},
            assignment_acceptor(enable_route_poker));

        conf.define_option<bool>(
            "network",
            "blackhole-routes",
            ClientOnly,
            Default{true},
            Comment{
                "Enable / disable route configuration blackholes.",
                "When enabled lokinet will drop IPv4 and IPv6 traffic (when in exit mode) that is "
                "not",
                "handled in the exit configuration.  Enabled by default."},
            assignment_acceptor(blackhole_routes));

        conf.define_option<std::string>(
            "network",
            "ifname",
            Comment{
                "Interface name for lokinet traffic. If unset lokinet will look for a free name",
                "matching 'lokitunN', starting at N=0 (e.g. lokitun0, lokitun1, ...).",
            },
            assignment_acceptor(_if_name));

        conf.define_option<std::string>(
            "network",
            "ifaddr",
            Comment{
                "Local IP and range for lokinet traffic. For example, 172.16.0.1/16 to use",
                "172.16.0.1 for this machine and 172.16.x.y for remote peers. If omitted then",
                "lokinet will attempt to find an unused private range.",
            },
            [this](std::string arg) {
                if (auto maybe_range = IPRange::from_string(arg); maybe_range)
                {
                    log::critical(logcat, "Parsed local ip range from config: {}", *maybe_range);
                    _local_ip_range = *maybe_range;
                    _local_addr = _local_ip_range->address();
                    log::critical(logcat, "Parsed local addr from config: {}", *_local_addr);
                    _local_base_ip = _local_ip_range->base_ip();
                }
                else
                    throw std::invalid_argument{"[network]:ifaddr invalid value: '{}'"_format(arg)};
            });

        conf.define_option<bool>(
            "network",
            "enable-ipv6-tun",
            Default{false},
            assignment_acceptor(enable_ipv6),
            Comment{"Enable IPv6 addressing for lokinet virtual TUN device interface (default: off)"});

        conf.define_option<std::string>(
            "network",
            "ip6-range",
            ClientOnly,
            Comment{
                "For all IPv6 exit traffic you will use this as the base address bitwised or'd "
                "with the v4 address in use.To disable ipv6 set this to an empty value.",
                "!!! WARNING !!! Disabling ipv6 tunneling when you have ipv6 routes WILL lead to ",
                "de-anonymization as lokinet will no longer carry your ipv6 traffic.",
            },
            IP6RangeDefault,
            [this](std::string arg) {
                if (arg.empty())
                {
                    log::warning(
                        logcat,
                        "!!! Disabling ipv6 tunneling when you have ipv6 routes WILL lead to de-anonymization as "
                        "lokinet will no longer carry your ipv6 traffic !!!");
                    return;
                }

                if (not _base_ipv6_range->from_string(arg))
                {
                    throw std::invalid_argument{"[network]:ip6-range invalid value: '{}'"_format(arg)};
                }
            });

        conf.define_option<std::string>(
            "network",
            "mapaddr",
            ClientOnly,
            MultiValue,
            Comment{
                "Map a remote `.loki` address to always use a fixed local IP. For example:",
                "    mapaddr=<pubkey>.loki:172.16.0.10",
                "maps `<pubkey>.loki` to `172.16.0.10` instead of using the next available IP.",
                "The given IP address must be inside the range configured by ifaddr=, and the",
                "remote `.loki` cannot be an ONS address"},
            [this](std::string arg) {
                if (arg.empty())
                    return;

                const auto pos = arg.find(":");

                if (pos == std::string::npos)
                    throw std::invalid_argument{"[endpoint]:mapaddr invalid entry: {}"_format(arg)};

                auto addr_arg = arg.substr(0, pos);
                auto ip_arg = arg.substr(pos + 1);

                if (is_valid_sns(addr_arg))
                    throw std::invalid_argument{"`mapaddr` cannot take an ONS entry: {}"_format(arg)};

                if (auto maybe_raddr = NetworkAddress::from_network_addr(std::move(addr_arg)); maybe_raddr)
                {
                    ip_v ipv;
                    // ipv6
                    if (ip_arg.find(':') != std::string_view::npos)
                        ipv = ipv6{std::move(ip_arg)};
                    else
                        ipv = ipv4{std::move(ip_arg)};

                    _reserved_local_ips.emplace(std::move(*maybe_raddr), std::move(ipv));
                }
                else
                    throw std::invalid_argument{"[endpoint]:mapaddr invalid entry: {}"_format(arg)};
            });

        conf.define_option<std::string>(
            "network",
            "blacklist-snode",
            ClientOnly,
            MultiValue,
            Comment{
                "Adds a lokinet relay `.snode` address to the list of relays to avoid when",
                "building paths. Can be specified multiple times.",
            },
            [this](std::string arg) {
                RouterID id;
                if (not id.from_relay_address(arg))
                    throw std::invalid_argument{"Invalid RouterID: {}"_format(arg)};

                auto itr = snode_blacklist.emplace(std::move(id));
                if (not itr.second)
                    throw std::invalid_argument{"Duplicate blacklist-snode: {}"_format(arg)};
            });

        // TODO: support SRV records for routers, but for now client only
        conf.define_option<std::string>(
            "network",
            "srv",
            ClientOnly,
            MultiValue,
            Comment{
                "Specify SRV Records for services hosted on the SNApp for protocols that use SRV",
                "records for service discovery. Each line specifies a single SRV record as:",
                "    srv=_service._protocol priority weight port target.loki",
                "and can be specified multiple times as needed.",
                "For more info see",
                "https://docs.oxen.io/products-built-on-oxen/lokinet/snapps/hosting-snapps",
                "and general description of DNS SRV record configuration.",
            },
            [this](std::string arg) {
                auto maybe_srv = dns::SRVData::from_srv_string(arg);

                if (not maybe_srv)
                    throw std::invalid_argument{"Invalid SRV Record string: {}"_format(arg)};

                srv_records.emplace(std::move(*maybe_srv));
            });

        conf.define_option<int>(
            "network",
            "path-alignment-timeout",
            ClientOnly,
            Comment{
                "How long to wait (in seconds) for a path to align to a pivot router when "
                "establishing",
                "a path through the network to a remote .loki address.",
            },
            [this](int val) {
                if (val <= 0)
                    throw std::invalid_argument{"invalid path alignment timeout: " + std::to_string(val) + " <= 0"};
                path_alignment_timeout = std::chrono::seconds{val};
            });

        constexpr auto addrmap_errorstr = "Invalid entry in persist-addrmap-file:"sv;

        conf.define_option<fs::path>(
            "network",
            "persist-addrmap-file",
            ClientOnly,
            Comment{
                "If given this specifies a file in which to record mapped local tunnel addresses so",
                "the same local address will be used for the same lokinet address on reboot. If this",
                "is not specified then the local IP of remote lokinet targets will not persist across",
                "restarts of lokinet.",
            },
            [this, &addrmap_errorstr](fs::path file) {
                if (file.empty())
                    throw std::invalid_argument("persist-addrmap-file cannot be empty");

                if (not fs::exists(file))
                    throw std::invalid_argument("persist-addrmap-file path invalid: {}"_format(file));

                bool load_file = true;
                {
                    constexpr auto ADDR_PERSIST_MODIFY_WINDOW = 1min;
                    const auto last_write_time = fs::last_write_time(file);
                    const auto now = decltype(last_write_time)::clock::now();

                    if (now < last_write_time or now - last_write_time > ADDR_PERSIST_MODIFY_WINDOW)
                    {
                        load_file = false;
                    }
                }

                std::vector<char> data;

                if (auto maybe = util::OpenFileStream<std::ifstream>(file, std::ios_base::binary); maybe and load_file)
                {
                    log::debug(logcat, "Config loading persisting address map file from path:{}", file);

                    maybe->seekg(0, std::ios_base::end);
                    const size_t len = maybe->tellg();

                    maybe->seekg(0, std::ios_base::beg);
                    data.resize(len);

                    log::trace(logcat, "Config reading {}B", len);

                    maybe->read(data.data(), data.size());
                }
                else
                {
                    auto err = "Config could not load persisting address map file from path:{}"_format(file);

                    log::warning(logcat, "{} {}", err, load_file ? "NOT FOUND" : "STALE");
                }

                if (not data.empty())
                {
                    std::string_view bdata{data.data(), data.size()};

                    log::trace(logcat, "Config parsing address map data: {}", bdata);

                    const auto parsed = oxenc::bt_deserialize<oxenc::bt_dict>(bdata);

                    for (const auto& [key, value] : parsed)
                    {
                        try
                        {
                            oxen::quic::Address addr{key, 0};

                            ip_v _ip;

                            if (addr.is_ipv4())
                                _ip = addr.to_ipv4();
                            else
                                _ip = addr.to_ipv6();

                            if (_ip == _local_base_ip)
                                continue;

                            if (not _local_ip_range->contains(_ip))
                            {
                                log::warning(
                                    logcat,
                                    "{}: {}",
                                    addrmap_errorstr,
                                    "out of range IP! (local range:{}, IP:{})"_format(*_local_ip_range, addr.host()));
                                continue;
                            }

                            const auto* arg = std::get_if<std::string>(&value);

                            if (not arg)
                            {
                                log::warning(logcat, "{}: {}", addrmap_errorstr, "not a string!");
                                continue;
                            }

                            if (is_valid_sns(*arg))
                            {
                                log::warning(logcat, "{}: {}", addrmap_errorstr, "cannot accept ONS names!");
                                continue;
                            }

                            if (auto maybe_netaddr = NetworkAddress::from_network_addr(*arg))
                            {
                                _reserved_local_ips.emplace(std::move(*maybe_netaddr), std::move(_ip));
                            }
                            else
                                log::warning(logcat, "{}: {}", addrmap_errorstr, *arg);
                        }
                        catch (const std::exception& e)
                        {
                            log::warning(
                                logcat,
                                "Exception caught parsing key:value (key:{}) pair in addr persist file:{}",
                                key,
                                e.what());
                        }
                    }
                }

                addr_map_persist_file = file;
            });

        // Deprecated options:
        conf.define_option<std::string>("network", "enabled", Deprecated);
    }

    void DnsConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        (void)params;

        // Most non-linux platforms have loopback as 127.0.0.1/32, but linux uses 127.0.0.1/8 so
        // that we can bind to other 127.* IPs to avoid conflicting with something else that may be
        // listening on 127.0.0.1:53.
        constexpr std::array DefaultDNSBind{
#ifdef __linux__
#ifdef WITH_SYSTEMD
            // when we have systemd support add a random high port on loopback as well
            // see https://github.com/oxen-io/lokinet/issues/1887#issuecomment-1091897282
            Default{"127.0.0.1:0"},
#endif
            Default{"127.3.2.1:53"},
#else
            Default{"127.0.0.1:53"},
#endif
        };

        auto parse_addr_for_dns = [](const std::string& arg) {
            std::optional<oxen::quic::Address> addr = std::nullopt;
            std::string_view arg_v{arg}, port;
            std::string host;
            uint16_t p{DEFAULT_DNS_PORT};

            if (auto pos = arg_v.find(':'); pos != arg_v.npos)
            {
                host = arg_v.substr(0, pos);
                port = arg_v.substr(pos + 1);

                if (not llarp::parse_int<uint16_t>(port, p))
                    log::info(logcat, "Failed to parse port in arg:{}, defaulting to DNS port 53", port);

                addr = oxen::quic::Address{host, p};
            }

            return addr;
        };

        conf.define_option<std::string>(
            "dns",
            "upstream",
            MultiValue,
            Comment{
                "Upstream resolver(s) to use as fallback for non-loki addresses.",
                "Multiple values accepted.",
            },
            [this, parse_addr_for_dns](std::string arg) mutable {
                if (not arg.empty())
                {
                    if (auto maybe_addr = parse_addr_for_dns(arg))
                        _upstream_dns.push_back(std::move(*maybe_addr));
                    else
                        log::warning(logcat, "Failed to parse upstream DNS resolver address:{}", arg);
                }
            });

        conf.define_option<bool>(
            "dns",
            "l3-intercept",
            Default{
                platform::is_windows or platform::is_android or (platform::is_macos and not platform::is_apple_sysex)},
            Comment{"Intercept all dns traffic (udp/53) going into our lokinet network interface "
                    "instead of binding a local udp socket"},
            assignment_acceptor(l3_intercept));

        conf.define_option<std::string>(
            "dns",
            "query-bind",
#if defined(_WIN32)
            Default{"0.0.0.0:0"},
#else
            Hidden,
#endif
            Comment{
                "Address to bind to for sending upstream DNS requests.",
            },
            [this, parse_addr_for_dns](std::string arg) mutable {
                if (not arg.empty())
                {
                    if (auto maybe_addr = parse_addr_for_dns(arg))
                        _query_bind = std::move(*maybe_addr);
                    else
                        log::warning(logcat, "Failed to parse bind address for DNS queries:{}", arg);
                }
            });

        conf.define_option<std::string>(
            "dns",
            "bind",
            DefaultDNSBind,
            MultiValue,
            Comment{
                "Address to bind to for handling DNS requests.",
            },
            [this, parse_addr_for_dns](std::string arg) mutable {
                if (not arg.empty())
                {
                    if (auto maybe_addr = parse_addr_for_dns(arg))
                    {
                        _bind_addrs.push_back(std::move(*maybe_addr));
                    }
                    else
                        log::warning(logcat, "Failed to parse bind address for handling DNS requests:{}", arg);
                }
            });

        conf.define_option<fs::path>(
            "dns",
            "add-hosts",
            ClientOnly,
            Comment{"Add a hosts file to the dns resolver", "For use with client side dns filtering"},
            [=, this](fs::path path) {
                if (path.empty())
                    return;
                if (not fs::exists(path))
                    throw std::invalid_argument{"cannot add hosts file {} as it does not exist"_format(path)};
                hostfiles.emplace_back(std::move(path));
            });

        // Ignored option (used by the systemd service file to disable resolvconf configuration).
        conf.define_option<bool>(
            "dns",
            "no-resolvconf",
            ClientOnly,
            Comment{
                "Can be uncommented and set to 1 to disable resolvconf configuration of lokinet "
                "DNS.",
                "(This is not used directly by lokinet itself, but by the lokinet init scripts",
                "on systems which use resolveconf)",
            });

        // forward the rest to libunbound
        conf.add_undeclared_handler(
            "dns", [this](auto, std::string_view key, std::string_view val) { extra_opts.emplace(key, val); });
    }

    void LinksConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        conf.add_section_comments(
            "bind",
            {
                "This section allows specifying the IPs that lokinet uses for incoming and "
                "outgoing",
                "connections.  For simple setups it can usually be left blank, but may be required",
                "for routers with multiple IPs, or routers that must listen on a private IP with",
                "forwarded public traffic.  It can also be useful for clients that want to use a",
                "consistent outgoing port for which firewall rules can be configured.",
            });

        const auto* net_ptr = params.net_ptr();

        conf.define_option<std::string>(
            "bind",
            "public-ip",
            Hidden,
            RelayOnly,
            Comment{
                "The IP address to advertise to the network instead of the incoming= or "
                "auto-detected",
                "IP.  This is typically required only when incoming= is used to listen on an "
                "internal",
                "private range IP address that received traffic forwarded from the public IP.",
            },
            [this](std::string arg) {
                public_addr = std::move(arg);
                log::warning(
                    logcat,
                    "Using deprecated option; pass this value to [Router]:public-ip instead "
                    "PLEASE");
            });

        conf.define_option<uint16_t>(
            "bind",
            "public-port",
            Hidden,
            RelayOnly,
            Comment{
                "The port to advertise to the network instead of the incoming= (or default) port.",
                "This is typically required only when incoming= is used to listen on an internal",
                "private range IP address/port that received traffic forwarded from the public IP.",
            },
            [this](uint16_t arg) {
                if (arg <= 0 || arg > std::numeric_limits<uint16_t>::max())
                    throw std::invalid_argument("public-port must be >= 0 and <= 65536");
                public_port = arg;
                log::warning(
                    logcat,
                    "Using deprecated option; pass this value to [Router]:public-port instead "
                    "PLEASE");
            });

        auto parse_addr_for_link = [net_ptr](const std::string& arg, bool& given_port_only) {
            std::optional<oxen::quic::Address> maybe = std::nullopt;
            std::string_view arg_v{arg};
            std::string host;
            uint16_t p{};

            if (auto pos = arg_v.find(':'); pos != arg_v.npos)
            {
                // host = arg_v.substr(0, pos);
                std::tie(host, p) = detail::parse_addr(arg_v, DEFAULT_LISTEN_PORT);
            }

            if (host.empty())
            {
                log::debug(logcat, "Host value empty, port:{}{}", p, p == DEFAULT_LISTEN_PORT ? "(DEFAULT PORT)" : "");
                given_port_only = p != DEFAULT_LISTEN_PORT;
                maybe = net_ptr->get_best_public_address(true, p);
            }
            else
                maybe = oxen::quic::Address{host, p};

            if (maybe and maybe->is_loopback())
                throw std::invalid_argument{"{} is a loopback address"_format(arg)};

            log::trace(logcat, "parsed address: {}", *maybe);

            return maybe;
        };

        conf.define_option<std::string>(
            "bind",
            "listen",
            Comment{
                "IP and/or port for lokinet to bind to for inbound/outbound connections.",
                "",
                "If IP is omitted then lokinet will search for a local network interface with a",
                "public IP address and use that IP (and will exit with an error if no such IP is "
                "found",
                "on the system).  If port is omitted then lokinet defaults to 1090.",
                "",
                "Note: only one address will be accepted. If this option is not specified, it "
                "will ",
                "default",
                "to the inbound or outbound value. Conversely, specifying this option will "
                "supercede ",
                "the",
                "deprecated inbound/outbound opts.",
                "",
                "Examples:",
                "    listen=15.5.29.5:443",
                "    listen=10.0.2.2",
                "    listen=:1234",
                "",
                "Using a private range IP address (like the second example entry) will require "
                "using",
                "the public-ip= and public-port= to specify the public IP address at which this",
                "router can be reached.",
            },
            [this, parse_addr_for_link](const std::string& arg) {
                if (auto a = parse_addr_for_link(arg, only_user_port))
                {
                    if (not a->is_addressable())
                        throw std::invalid_argument{"Listen address ({}) is not addressible!"_format(*a)};

                    listen_addr = *a;
                    using_new_api = true;
                }
                else
                    throw std::invalid_argument{"Could not parse listen address!"};
            });

        conf.define_option<std::string>(
            "bind", "inbound", RelayOnly, MultiValue, Hidden, [this, parse_addr_for_link](const std::string& arg) {
                if (using_new_api)
                    throw std::runtime_error{"USE THE NEW API -- SPECIFY LOCAL ADDRESS UNDER [LISTEN]"};

                if (auto a = parse_addr_for_link(arg, only_user_port); a)
                {
                    if (a->is_addressable() or (!a->is_any_port() and only_user_port))
                    {
                        log::warning(
                            logcat,
                            "Loaded address {} from deprecated [inbound] options; update your config to "
                            "use "
                            "[bind]:listen instead PLEASE",
                            *a);
                        listen_addr = *a;
                    }
                }
            });

        conf.define_option<std::string>("bind", "outbound", MultiValue, Deprecated, Hidden);

        conf.add_undeclared_handler("bind", [this](std::string_view, std::string_view key, std::string_view val) {
            if (using_new_api)
                throw std::runtime_error{"USE THE NEW API -- SPECIFY LOCAL ADDRESS UNDER [LISTEN]"};

            log::warning(logcat, "Please update your config to use [bind]:listen instead");

            uint16_t port{0};

            if (auto rv = llarp::parse_int<uint16_t>(val, port); not rv)
                throw std::runtime_error{"Could not parse port; stop using this deprecated handler"};

            port = port == 0 ? DEFAULT_LISTEN_PORT : port;

            // special case: wildcard for outbound
            if (key == "*")
            {
                log::warning(
                    logcat,
                    "Wildcat address referencing port {} is referencing deprecated outbound "
                    "config "
                    "options; use [bind]:listen instead",
                    port);
                return;
            }

            oxen::quic::Address temp;

            try
            {
                temp = oxen::quic::Address{std::string{key}, port};
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error{
                    "Could not parse address {}; please update your config to use "
                    "[bind]:listen "
                    "instead: {}"_format(key, e.what())};
            }

            if (not temp.is_addressable())
            {
                throw std::runtime_error{
                    "Invalid address: {}; stop using this deprecated handler, update your "
                    "config to "
                    "use "
                    "[bind]:listen instead PLEASE"_format(temp)};
            }

            listen_addr = std::move(temp);
            only_user_port = true;
        });
    }

    void ApiConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        constexpr std::array DefaultRPCBind{
            Default{"tcp://127.0.0.1:1190"},
#ifndef _WIN32
            Default{"ipc://rpc.sock"},
#endif
        };

        conf.define_option<bool>(
            "api",
            "enabled",
            Default{not params.is_relay},
            assignment_acceptor(enable_rpc_server),
            Comment{
                "Determines whether or not the LMQ JSON API is enabled. Defaults ON/OFF for client/relays",
            });

        conf.define_option<std::string>(
            "api",
            "bind",
            DefaultRPCBind,
            MultiValue,
            [this, first = true](std::string arg) mutable {
                if (first)
                {
                    rpc_bind_addrs.clear();
                    first = false;
                }
                if (arg.find("://") == std::string::npos)
                {
                    arg = "tcp://" + arg;
                }
                rpc_bind_addrs.emplace_back(arg);
            },
            Comment{
                "IP addresses and ports to bind to.",
                "Recommend localhost-only for security purposes.",
            });

        conf.define_option<std::string>("api", "authkey", Deprecated);

        // TODO: this was from pre-refactor:
        // TODO: add pubkey to whitelist
    }

    void LokidConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        (void)params;
        conf.define_option<bool>(
            "lokid",
            "disable-testing",
            Default{false},
            Hidden,
            RelayOnly,
            Comment{"Development option: set to true to disable reachability testing when using ", "testnet"},
            assignment_acceptor(disable_testing));

        conf.define_option<std::string>(
            "lokid",
            "rpc",
            RelayOnly,
            Required,
            Comment{
                "oxenmq control address for for communicating with oxend. Depends on oxend's",
                "lmq-local-control configuration option. By default this value should be",
                "ipc://OXEND-DATA-DIRECTORY/oxend.sock, such as:",
                "    rpc=ipc:///var/lib/oxen/oxend.sock",
                "    rpc=ipc:///home/USER/.oxen/oxend.sock",
                "but can use (non-default) TCP if oxend is configured that way:",
                "    rpc=tcp://127.0.0.1:5678",
            },
            [this](std::string arg) { rpc_addr = oxenmq::address(arg); });

        // Deprecated options:
        conf.define_option<std::string>("lokid", "jsonrpc", RelayOnly, Hidden, [](std::string arg) {
            if (arg.empty())
                return;
            throw std::invalid_argument(
                "the [lokid]:jsonrpc option is no longer supported; please use the [lokid]:rpc "
                "config "
                "option instead with oxend's lmq-local-control address -- typically a value such "
                "as "
                "rpc=ipc:///var/lib/oxen/oxend.sock or rpc=ipc:///home/snode/.oxen/oxend.sock");
        });
        conf.define_option<bool>("lokid", "enabled", RelayOnly, Deprecated);
        conf.define_option<std::string>("lokid", "username", Deprecated);
        conf.define_option<std::string>("lokid", "password", Deprecated);
        conf.define_option<std::string>("lokid", "service-node-seed", Deprecated);
    }

    void BootstrapConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        (void)params;

        conf.define_option<bool>(
            "bootstrap",
            "seed-node",
            Default{false},
            Comment{"Whether or not to run as a seed node. We will not have any bootstrap routers "
                    "configured."},
            assignment_acceptor(seednode));

        conf.define_option<std::string>(
            "bootstrap",
            "add-node",
            MultiValue,
            Comment{
                "Specify a bootstrap file containing a list of signed RelayContacts of service "
                "nodes",
                "which can act as a bootstrap. Can be specified multiple times.",
            },
            [this](std::string arg) {
                if (arg.empty())
                    throw std::invalid_argument("cannot use empty filename as bootstrap");

                files.emplace_back(std::move(arg));

                if (not fs::exists(files.back()))
                    throw std::invalid_argument("file does not exist: " + arg);
            });
    }

    void LoggingConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        (void)params;

        constexpr Default DefaultLogType{platform::is_android or platform::is_apple ? "system" : "print"};
        constexpr Default DefaultLogFile{""};

        const Default DefaultLogLevel{params.is_relay ? "warn" : "info"};

        conf.define_option<std::string>(
            "logging",
            "type",
            DefaultLogType,
            [this](std::string arg) { type = log::type_from_string(arg); },
            Comment{
                "Log type (format). Valid options are:",
                "  print - print logs to standard output",
                "  system - logs directed to the system logger (syslog/eventlog/etc.)",
                "  file - plaintext formatting to a file",
            });

        conf.define_option<std::string>(
            "logging",
            "level",
            DefaultLogLevel,
            [this](std::string arg) { level = log::level_from_string(arg); },
            Comment{
                "Minimum log level to print. Logging below this level will be ignored.",
                "Valid log levels, in ascending order, are:",
                "  trace",
                "  debug",
                "  info",
                "  warn",
                "  error",
                "  critical",
                "  none",
            });

        conf.define_option<std::string>(
            "logging",
            "file",
            DefaultLogFile,
            assignment_acceptor(file),
            Comment{
                "When using type=file this is the output filename.",
            });
    }

    void PeerSelectionConfig::define_config_options(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        (void)params;

        constexpr Default DefaultUniqueCIDR{24};

        conf.define_option<int>(
            "paths",
            "unique-range-size",
            DefaultUniqueCIDR,
            ClientOnly,
            [=, this](int arg) {
                if (arg > 32 or arg < 4)
                    throw std::invalid_argument{"[paths]:unique-range-size must be between 4 and 32"};

                unique_hop_netmask = static_cast<uint8_t>(arg);
            },
            Comment{
                "Netmask for router path selection; each router must be from a distinct IPv4 "
                "subnet",
                "of the given size.",
                "E.g. 16 ensures that all routers are using IPs from distinct /16 IP ranges."});

#ifdef WITH_GEOIP
        conf.defineOption<std::string>(
            "paths",
            "exclude-country",
            ClientOnly,
            MultiValue,
            [=](std::string arg) { m_ExcludeCountries.emplace(lowercase_ascii_string(std::move(arg))); },
            Comment{
                "Exclude a country given its 2 letter country code from being used in path builds.",
                "For example:",
                "    exclude-country=DE",
                "would avoid building paths through routers with IPs in Germany.",
                "This option can be specified multiple times to exclude multiple countries"});
#endif
    }

    bool PeerSelectionConfig::check_rcs(const std::set<RemoteRC>& rcs) const
    {
        if (unique_hop_netmask == 0)
            return true;

        std::set<IPRange> seen_ranges;

        for (const auto& hop : rcs)
        {
            if (auto [it, b] = seen_ranges.emplace(hop.addr(), unique_hop_netmask); not b)
                return false;
        }

        return true;
    }

    std::unique_ptr<ConfigGenParameters> Config::make_gen_params() const
    {
        return std::make_unique<ConfigGenParameters_impl>();
    }

    Config::Config(std::optional<fs::path> datadir) : data_dir{datadir ? std::move(*datadir) : fs::current_path()} {}

    constexpr auto GetOverridesDir = [](auto datadir) -> fs::path { return datadir / "conf.d"; };

    void Config::save()
    {
        const auto overridesDir = GetOverridesDir(data_dir);
        if (not fs::exists(overridesDir))
            fs::create_directory(overridesDir);
        parser.save();
    }

    void Config::override(std::string section, std::string key, std::string value)
    {
        parser.add_override(GetOverridesDir(data_dir) / "overrides.ini", section, key, value);
    }

    void Config::load_overrides(ConfigDefinition& conf) const
    {
        ConfigParser parser;
        const auto overridesDir = GetOverridesDir(data_dir);
        if (fs::exists(overridesDir))
        {
            for (const auto& f : fs::directory_iterator{overridesDir})
            {
                if (not f.is_regular_file() or f.path().extension() != ".ini")
                    continue;
                ConfigParser parser;
                if (not parser.load_file(f.path()))
                    throw std::runtime_error{"cannot load file at path:{}"_format(f.path().string())};

                parser.iter_all_sections([&](std::string_view section, const SectionValues& values) {
                    for (const auto& [k, v] : values)
                        conf.add_config_value(section, k, v);
                });
            }
        }
    }

    void Config::add_default(std::string section, std::string key, std::string val)
    {
        additional.emplace_back(std::array<std::string, 3>{section, key, val});
    }

    bool Config::load_config_data(std::string_view ini, std::optional<fs::path> filename, bool isRelay)
    {
        auto params = make_gen_params();
        params->is_relay = isRelay;
        params->default_data_dir = data_dir;
        ConfigDefinition conf{isRelay};
        add_backcompat_opts(conf);
        init_config(conf, *params);

        for (const auto& item : additional)
        {
            conf.add_config_value(item[0], item[1], item[2]);
        }

        parser.clear();

        if (filename)
            parser.set_filename(*filename);
        else
            parser.set_filename(fs::path{});

        if (not parser.load_from_str(ini))
            return false;

        parser.iter_all_sections([&](std::string_view section, const SectionValues& values) {
            for (const auto& pair : values)
            {
                conf.add_config_value(section, pair.first, pair.second);
            }
        });

        load_overrides(conf);

        conf.process();

        return true;
    }

    bool Config::load(std::optional<fs::path> fname, bool isRelay)
    {
        std::string ini;
        if (fname)
        {
            try
            {
                ini = util::file_to_string(*fname);
            }
            catch (const std::exception&)
            {
                return false;
            }
        }
        return load_config_data(ini, fname, isRelay);
    }

    bool Config::load_string(std::string_view ini, bool isRelay)
    {
        return load_config_data(ini, std::nullopt, isRelay);
    }

    bool Config::load_default_config(bool isRelay) { return load_string("", isRelay); }

    void Config::init_config(ConfigDefinition& conf, const ConfigGenParameters& params)
    {
        router.define_config_options(conf, params);
        exit.define_config_options(conf, params);
        network.define_config_options(conf, params);
        paths.define_config_options(conf, params);
        dns.define_config_options(conf, params);
        links.define_config_options(conf, params);
        api.define_config_options(conf, params);
        lokid.define_config_options(conf, params);
        bootstrap.define_config_options(conf, params);
        logging.define_config_options(conf, params);
    }

    void Config::add_backcompat_opts(ConfigDefinition& conf)
    {
        // These config sections don't exist anymore:

        conf.define_option<std::string>("system", "user", Deprecated);
        conf.define_option<std::string>("system", "group", Deprecated);
        conf.define_option<std::string>("system", "pidfile", Deprecated);

        conf.define_option<std::string>("netdb", "dir", Deprecated);

        conf.define_option<std::string>("metrics", "json-metrics-path", Deprecated);
    }

    void ensure_config(fs::path dataDir, fs::path confFile, bool overwrite, bool asRouter)
    {
        // fail to overwrite if not instructed to do so
        if (fs::exists(confFile) && !overwrite)
        {
            log::debug(logcat, "Config file already exists; NOT creating new config");
            return;
        }

        const auto parent = confFile.parent_path();

        // create parent dir if it doesn't exist
        if ((not parent.empty()) and (not fs::exists(parent)))
        {
            fs::create_directory(parent);
        }

        log::info(
            logcat,
            "Attempting to create config file for {} at file path:{}",
            asRouter ? "router" : "client",
            confFile);

        llarp::Config config{dataDir};
        std::string confStr;
        if (asRouter)
            confStr = config.generate_router_config_base();
        else
            confStr = config.generate_client_config_base();

        // open a filestream
        try
        {
            util::buffer_to_file(confFile, confStr);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error{"Failed to write config data to {}: {}"_format(confFile, e.what())};
        }

        log::info(logcat, "Generated new config (path: {})", confFile);
    }

    void generate_common_config_comments(ConfigDefinition& def)
    {
        // router
        def.add_section_comments(
            "router",
            {
                "Configuration for routing activity.",
            });

        // logging
        def.add_section_comments(
            "logging",
            {
                "logging settings",
            });

        // api
        def.add_section_comments(
            "api",
            {
                "JSON API settings",
            });

        // dns
        def.add_section_comments(
            "dns",
            {
                "DNS configuration",
            });

        // bootstrap
        def.add_section_comments(
            "bootstrap",
            {
                "Configure nodes that will bootstrap us onto the network",
            });

        // network
        def.add_section_comments(
            "network",
            {
                "Network settings",
            });
    }

    std::string Config::generate_client_config_base()
    {
        auto params = make_gen_params();
        params->is_relay = false;
        params->default_data_dir = data_dir;

        llarp::ConfigDefinition def{false};
        init_config(def, *params);
        generate_common_config_comments(def);
        def.add_section_comments(
            "paths",
            {
                "path selection algorithm options",
            });

        def.add_section_comments(
            "network",
            {
                "Snapp settings",
            });

        return def.generate_ini_config(true);
    }

    std::string Config::generate_router_config_base()
    {
        auto params = make_gen_params();
        params->is_relay = true;
        params->default_data_dir = data_dir;

        llarp::ConfigDefinition def{true};
        init_config(def, *params);
        generate_common_config_comments(def);

        // oxend
        def.add_section_comments(
            "lokid",
            {
                "Settings for communicating with oxend",
            });

        return def.generate_ini_config(true);
    }

    std::shared_ptr<Config> Config::make_embedded_config()
    {
        auto config = std::make_shared<Config>();
        config->load();
        config->logging.level = log::Level::off;
        config->api.enable_rpc_server = false;
        config->network.init_tun = false;
        config->network.save_profiles = false;
        config->bootstrap.files.clear();
        return config;
    }

}  // namespace llarp
