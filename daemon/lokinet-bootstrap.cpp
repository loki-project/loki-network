#include <llarp/constants/files.hpp>
#include <llarp/constants/version.hpp>

#include <cpr/cpr.h>

#include <iostream>
#include <unordered_map>
#include <unordered_set>

#ifndef _WIN32
#include <openssl/x509.h>
#endif

namespace
{
    int fail(std::string msg)
    {
        std::cout << msg << std::endl;
        return 1;
    }

    int print_help(std::string exe)
    {
        std::cout << R"(Lokinet bootstrap.signed fetchy program thing

Downloads the initial bootstrap.signed for lokinet into a local file from a
default or user defined server via the reachable network.

Usage: )" << exe << R"( [bootstrap_url [output_file]]

bootstrap_url can be specified as a full URL, or a special named value
("mainnet" or "testnet") to download from the pre-defined mainnet or testnet
bootstrap URLs.

)";
        return 0;
    }

}  // namespace

int main(int argc, char* argv[])
{
    const std::unordered_map<std::string, std::string> bootstrap_urls = {
        {"lokinet", "https://seed.lokinet.org/lokinet.signed"}, {"testnet", "https://seed.lokinet.org/testnet.signed"}};

    std::string bootstrap_url = bootstrap_urls.at("lokinet");
    fs::path outputfile{llarp::GetDefaultBootstrap()};

    const std::unordered_set<std::string> help_args = {"-h", "--help"};

    for (int idx = 1; idx < argc; idx++)
    {
        const std::string arg{argv[idx]};
        if (help_args.count(arg))
            return print_help(argv[0]);
    }

    if (argc > 1)
    {
        if (auto itr = bootstrap_urls.find(argv[1]); itr != bootstrap_urls.end())
        {
            bootstrap_url = itr->second;
        }
        else
        {
            bootstrap_url = argv[1];
        }
    }
    if (argc > 2)
    {
        outputfile = fs::path{argv[2]};
    }
    std::cout << "fetching " << bootstrap_url << std::endl;
    cpr::Response resp =
#ifdef _WIN32
        cpr::Get(cpr::Url{bootstrap_url}, cpr::Header{{"User-Agent", std::string{llarp::VERSION_FULL}}});
#else
        cpr::Get(
            cpr::Url{bootstrap_url},
            cpr::Header{{"User-Agent", std::string{llarp::LOKINET_VERSION_FULL}}},
            cpr::Ssl(cpr::ssl::CaPath{X509_get_default_cert_dir()}));
#endif
    if (resp.status_code != 200)
    {
        return fail("failed to fetch '" + bootstrap_url + "' HTTP " + std::to_string(resp.status_code));
    }

    const auto& data = resp.text;

    if (data[0] == 'l' or data[0] == 'd')
    {
        try
        {
            std::cout << "writing bootstrap file to: " << outputfile << std::endl;
            std::ofstream ofs{outputfile, std::ios::binary};
            ofs.exceptions(std::ofstream::failbit);
            ofs << data;
            return 0;
        }
        catch (std::exception& ex)
        {
            return fail(std::string{"failed to write bootstrap file: "} + ex.what());
        }
    }
    return fail("got invalid bootstrap file content");
}
