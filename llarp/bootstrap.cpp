#include "bootstrap.hpp"

#include "util/file.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"

namespace llarp
{
    static auto logcat = log::Cat("Bootstrap");

    bool BootstrapList::bt_decode(std::string_view buf)
    {
        const auto& f = buf.front();

        switch (f)
        {
            case 'l':
                return bt_decode_list(buf);
            case 'd':
                return bt_decode_dict(buf);
            default:
                log::critical(logcat, "Unable to parse bootstrap as bt list or dict!");
                return false;
        }
    }

    bool BootstrapList::bt_decode_dict(std::string_view buf)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        bool ret = true;

        try
        {
            ret &= emplace(buf).second;
        }
        catch (...)
        {
            log::warning(logcat, "Unable to decode bootstrap RemoteRC");
            return false;
        }

        _curr = begin();
        return ret;
    }

    bool BootstrapList::bt_decode_list(std::string_view buf)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        bool ret = true;

        try
        {
            oxenc::bt_list_consumer btlc{buf};

            while (not btlc.is_finished())
                ret &= emplace(btlc.consume_dict_data()).second;
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Unable to decode bootstrap RemoteRC: {}", e.what());
            return false;
        }

        _curr = begin();
        return ret;
    }

    bool BootstrapList::contains(const RouterID& rid) const
    {
        for (const auto& it : *this)
        {
            if (it.router_id() == rid)
                return true;
        }

        return false;
    }

    bool BootstrapList::contains(const RemoteRC& rc) const
    {
        return count(rc);
    }

    std::string_view BootstrapList::bt_encode() const
    {
        oxenc::bt_list_producer btlp{};

        for (const auto& it : *this)
            btlp.append(it.view());

        return btlp.view();
    }

    void BootstrapList::populate_bootstraps(std::vector<fs::path> paths, const fs::path& def, bool load_fallbacks)
    {
        for (const auto& f : paths)
        {
            // TESTNET: TODO: revise fucked config
            log::trace(logcat, "Loading BootstrapRC from file at path:{}", f);
            if (not read_from_file(f))
                throw std::invalid_argument{"User-provided BootstrapRC is invalid!"};
        }

        if (empty())
        {
            log::trace(logcat, "BootstrapRC list empty; looking for default BootstrapRC from file at path:{}", def);
            read_from_file(def);
        }

        for (auto itr = begin(); itr != end(); ++itr)
        {
            if (RelayContact::is_obsolete(*itr))
            {
                log::debug(logcat, "Deleting obsolete BootstrapRC (rid:{})", itr->router_id());
                itr = erase(itr);
                continue;
            }
        }

        // TESTNET: force load fallbacks
        if (/* empty() and  */ load_fallbacks)
        {
            // log::critical(logcat, "BootstrapRC list empty; loading fallbacks...");
            log::critical(logcat, "BootstrapRC list force loading fallbacks...");
            auto fallbacks = llarp::load_bootstrap_fallbacks();

            if (auto itr = fallbacks.find(RelayContact::ACTIVE_NETID); itr != fallbacks.end())
            {
                log::debug(logcat, "Loading {} default fallback bootstrap router(s)!", itr->second.size());
                log::critical(logcat, "Fallback bootstrap loaded: {}", itr->second.current());
                merge(itr->second);
            }

            if (empty())
            {
                log::error(
                    logcat,
                    "No Bootstrap routers were loaded.  The default Bootstrap file {} does not "
                    "exist, and "
                    "loading fallback Bootstrap RCs failed.",
                    def);

                throw std::runtime_error("No Bootstrap nodes available.");
            }
        }

        log::debug(logcat, "We have {} Bootstrap router(s)!", size());
        _curr = begin();
    }

    bool BootstrapList::read_from_file(const fs::path& fpath)
    {
        bool result = false;

        if (not fs::exists(fpath))
        {
            log::critical(logcat, "Bootstrap RC file non-existant at path:{}", fpath);
            return result;
        }

        auto content = util::file_to_string(fpath);
        result = bt_decode(content);

        log::trace(
            logcat,
            "{}uccessfully loaded BootstrapRC file ({}B) at path:{}, contents: {}",
            result ? "S" : "Uns",
            content.size(),
            fpath,
            buffer_printer{content});

        _curr = begin();
        return result;
    }
}  // namespace llarp
