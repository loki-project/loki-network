#pragma once

#include <llarp/contact/router_contact.hpp>
#include <llarp/crypto/crypto.hpp>

#include <set>
#include <unordered_map>

namespace llarp
{
    struct BootstrapList final : public std::set<RemoteRC>
    {
        std::set<RemoteRC>::iterator _curr = begin();

        const RemoteRC& current() { return *_curr; }

        bool bt_decode(std::string_view buf);

        bool bt_decode_dict(std::string_view buf);

        bool bt_decode_list(std::string_view buf);

        bool bt_decode(oxenc::bt_list_consumer btlc);

        bool bt_decode(oxenc::bt_dict_consumer btdc);

        std::string_view bt_encode() const;

        void populate_bootstraps(std::vector<fs::path> paths, const fs::path& def, bool load_fallbacks);

        bool read_from_file(const fs::path& fpath);

        bool contains(const RouterID& rid) const;

        // returns a reference to the next bootstrap in the list
        const RemoteRC& next()
        {
            if (size() < 2)
                return *_curr;

            ++_curr;

            if (_curr == this->end())
                _curr = this->begin();

            return *_curr;
        }

        bool contains(const RemoteRC& rc) const;

        void randomize()
        {
            if (size() > 1)
                _curr = std::next(begin(), std::uniform_int_distribution<size_t>{0, size() - 1}(csrng));
        }

        void clear_list() { clear(); }
    };

    std::unordered_map<std::string, BootstrapList> load_bootstrap_fallbacks();

}  // namespace llarp
