#pragma once

#include <llarp/util/file.hpp>

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace llarp
{
    struct ConfigParser
    {
        using SectionValues = std::unordered_multimap<std::string, std::string>;
        using ConfigMap = std::unordered_map<std::string, SectionValues>;
        /// clear parser
        void clear();

        /// load config file for bootserv
        /// return true on success
        /// return false on error
        bool load_file(const fs::path& fname);

        /// load new .ini file from string (calls ParseAll() rather than Parse())
        /// return true on success
        /// return false on error
        bool load_new_from_str(std::string_view str);

        /// load from string
        /// return true on success
        /// return false on error
        bool load_from_str(std::string_view str);

        /// iterate all sections and thier values
        void iter_all_sections(std::function<void(std::string_view, const SectionValues&)> visit);

        /// visit a section in config read only by name
        /// return false if no section or value propagated from visitor
        bool visit_section(const char* name, std::function<bool(const SectionValues&)> visit) const;

        /// add a config option that is appended in another file
        void add_override(fs::path file, std::string section, std::string key, std::string value);

        /// save config overrides
        void save();

        /// save new .ini config file to path
        void save_new() const;

        void set_filename(const fs::path& f) { _filename = f; }

      private:
        bool parse_all();

        bool parse();

        std::string _data;
        ConfigMap _config;
        std::unordered_map<fs::path, ConfigMap, util::FileHash> _overrides;
        fs::path _filename;
    };

}  // namespace llarp
