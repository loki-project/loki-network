
#include "platform.hpp"

#ifdef _WIN32
#include "win32.hpp"
#endif
#ifdef __linux__
#ifdef ANDROID
#include "android.hpp"
#else
#include "linux.hpp"
#endif
#endif

namespace llarp::vpn
{
    const llarp::net::Platform* AbstractRouteManager::net_ptr() const
    {
        return llarp::net::Platform::Default_ptr();
    }

    std::shared_ptr<Platform> MakeNativePlatform(llarp::Context* ctx)
    {
        (void)ctx;
        std::shared_ptr<Platform> plat;
#ifdef _WIN32
        plat = std::make_shared<llarp::win32::VPNPlatform>(ctx);
#endif
#ifdef __linux__
#ifdef ANDROID
        plat = std::make_shared<vpn::AndroidPlatform>(ctx);
#else
        plat = std::make_shared<vpn::LinuxPlatform>();
#endif
#endif
#ifdef __APPLE__
        throw std::runtime_error{"not supported"};
#endif
        return plat;
    }

}  // namespace llarp::vpn
