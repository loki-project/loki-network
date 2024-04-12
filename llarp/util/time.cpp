#include "time.hpp"

namespace llarp
{
    using namespace std::literals;

    namespace
    {
        template <typename Res, typename Clock>
        static std::chrono::milliseconds time_since_epoch(std::chrono::time_point<Clock> point)
        {
            return std::chrono::duration_cast<Res>(point.time_since_epoch());
        }

        static const auto started_at_system = std::chrono::system_clock::now();

        static const auto started_at_steady = std::chrono::steady_clock::now();
    }  // namespace

    std::chrono::steady_clock::time_point get_time()
    {
        return std::chrono::steady_clock::now();
    }

    std::chrono::nanoseconds get_timestamp()
    {
        return std::chrono::steady_clock::now().time_since_epoch();
    }

    uint64_t to_milliseconds(std::chrono::milliseconds ms)
    {
        return ms.count();
    }

    /// get our uptime in ms
    std::chrono::milliseconds uptime()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started_at_steady);
    }

    rc_time time_point_now()
    {
        return std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
    }

    std::chrono::milliseconds time_now_ms()
    {
        auto t = uptime();
#ifdef TESTNET_SPEED
        t /= uint64_t{TESTNET_SPEED};
#endif
        return t + time_since_epoch<std::chrono::milliseconds, std::chrono::system_clock>(started_at_system);
    }

    nlohmann::json to_json(const std::chrono::milliseconds& t)
    {
        return to_milliseconds(t);
    }

    static auto extract_h_m_s_ms(const std::chrono::milliseconds& dur)
    {
        return std::make_tuple(
            std::chrono::duration_cast<std::chrono::hours>(dur).count(),
            (std::chrono::duration_cast<std::chrono::minutes>(dur) % 1h).count(),
            (std::chrono::duration_cast<std::chrono::seconds>(dur) % 1min).count(),
            (std::chrono::duration_cast<std::chrono::milliseconds>(dur) % 1s).count());
    }

    std::string short_time_from_now(
        const std::chrono::system_clock::time_point& t, const std::chrono::milliseconds& now_threshold)
    {
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::time_point::clock::now() - t);

        bool future = delta < 0s;
        if (future)
            delta = -delta;

        auto [hours, mins, secs, ms] = extract_h_m_s_ms(delta);

        auto in = future ? "in "sv : ""sv;
        auto ago = future ? ""sv : " ago"sv;
        return delta < now_threshold ? "now"s
            : delta < 10s            ? "{}{}.{:03d}s{}"_format(in, secs, ms, ago)
            : delta < 1h             ? "{}{}m{:02d}s{}"_format(in, mins, secs, ago)
                                     : "{}{}h{:02d}m{}"_format(in, hours, mins, ago);
    }

}  // namespace llarp
