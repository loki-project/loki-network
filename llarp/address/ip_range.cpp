#include "ip_range.hpp"

#include "utils.hpp"

namespace llarp
{
    bool IPRange::from_string(std::string arg)
    {
        if (auto pos = arg.find_first_of('/'); pos != std::string::npos)
        {
            try
            {
                auto [host, p] = parse_addr(arg.substr(0, pos), 0);
                assert(p == 0);
                addr = oxen::quic::Address{host, p};
                return parse_int(arg.substr(pos), mask);
            }
            catch (const std::exception& e)
            {
                log::error(logcat, "Exception caught parsing IPRange:{}", e.what());
                return false;
            }
        }

        return false;
    }
}  //  namespace llarp
