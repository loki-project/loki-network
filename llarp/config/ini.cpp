#include "ini.hpp"

#include <llarp/util/formattable.hpp>
#include <llarp/util/logging.hpp>

#include <cctype>
#include <fstream>
#include <list>
#include <stdexcept>

namespace llarp
{
    static auto logcat = log::Cat("config.ini");

    bool ConfigParser::load_file(const fs::path& fname)
    {
        try
        {
            _data = util::file_to_string(fname);
        }
        catch (const std::exception& e)
        {
            return false;
        }
        if (_data.empty())
            return false;

        _filename = fname;
        return parse();
    }

    bool ConfigParser::load_new_from_str(std::string_view str)
    {
        _data.resize(str.size());
        std::copy(str.begin(), str.end(), _data.begin());
        return parse_all();
    }

    bool ConfigParser::load_from_str(std::string_view str)
    {
        _data.resize(str.size());
        std::copy(str.begin(), str.end(), _data.begin());
        return parse();
    }

    void ConfigParser::clear()
    {
        _overrides.clear();
        _config.clear();
        _data.clear();
    }

    static bool whitespace(char ch)
    {
        return std::isspace(static_cast<unsigned char>(ch)) != 0;
    }

    /// Differs from Parse() as ParseAll() does NOT skip comments
    /// ParseAll() is only used by RPC endpoint 'config' for
    /// reading new .ini files from string and writing them
    bool ConfigParser::parse_all()
    {
        std::list<std::string_view> lines;
        {
            auto itr = _data.begin();
            // split into lines
            while (itr != _data.end())
            {
                auto beg = itr;
                while (itr != _data.end() && *itr != '\n' && *itr != '\r')
                    ++itr;
                lines.emplace_back(std::addressof(*beg), std::distance(beg, itr));
                if (itr == _data.end())
                    break;
                ++itr;
            }
        }

        std::string_view sectName;
        size_t lineno = 0;
        for (auto line : lines)
        {
            lineno++;
            // Trim whitespace
            while (!line.empty() && whitespace(line.front()))
                line.remove_prefix(1);
            while (!line.empty() && whitespace(line.back()))
                line.remove_suffix(1);

            // Skip blank lines but NOT comments
            if (line.empty())
                continue;

            if (line.front() == '[' && line.back() == ']')
            {
                // section header
                line.remove_prefix(1);
                line.remove_suffix(1);
                sectName = line;
            }
            else if (auto kvDelim = line.find('='); kvDelim != std::string_view::npos)
            {
                // key value pair
                std::string_view k = line.substr(0, kvDelim);
                std::string_view v = line.substr(kvDelim + 1);
                // Trim inner whitespace
                while (!k.empty() && whitespace(k.back()))
                    k.remove_suffix(1);
                while (!v.empty() && whitespace(v.front()))
                    v.remove_prefix(1);

                if (k.empty())
                {
                    throw std::runtime_error(fmt::format("{} invalid line ({}): '{}'", _filename, lineno, line));
                }

                log::debug(logcat, "{}:[{}]:{}={}", _filename, sectName, k, v);
                _config[std::string{sectName}].emplace(k, v);
            }
            else  // malformed?
            {
                throw std::runtime_error(fmt::format("{} invalid line ({}): '{}'", _filename, lineno, line));
            }
        }
        return true;
    }

    bool ConfigParser::parse()
    {
        std::list<std::string_view> lines;
        {
            auto itr = _data.begin();
            // split into lines
            while (itr != _data.end())
            {
                auto beg = itr;
                while (itr != _data.end() && *itr != '\n' && *itr != '\r')
                    ++itr;
                lines.emplace_back(std::addressof(*beg), std::distance(beg, itr));
                if (itr == _data.end())
                    break;
                ++itr;
            }
        }

        std::string_view sectName;
        size_t lineno = 0;
        for (auto line : lines)
        {
            lineno++;
            // Trim whitespace
            while (!line.empty() && whitespace(line.front()))
                line.remove_prefix(1);
            while (!line.empty() && whitespace(line.back()))
                line.remove_suffix(1);

            // Skip blank lines
            if (line.empty() or line.front() == ';' or line.front() == '#')
                continue;

            if (line.front() == '[' && line.back() == ']')
            {
                // section header
                line.remove_prefix(1);
                line.remove_suffix(1);
                sectName = line;
            }
            else if (auto kvDelim = line.find('='); kvDelim != std::string_view::npos)
            {
                // key value pair
                std::string_view k = line.substr(0, kvDelim);
                std::string_view v = line.substr(kvDelim + 1);
                // Trim inner whitespace
                while (!k.empty() && whitespace(k.back()))
                    k.remove_suffix(1);
                while (!v.empty() && whitespace(v.front()))
                    v.remove_prefix(1);

                if (k.empty())
                {
                    throw std::runtime_error(fmt::format("{} invalid line ({}): '{}'", _filename, lineno, line));
                }

                log::debug(logcat, "{}:[{}]:{}={}", _filename, sectName, k, v);
                _config[std::string{sectName}].emplace(k, v);
            }
            else  // malformed?
            {
                throw std::runtime_error(fmt::format("{} invalid line ({}): '{}'", _filename, lineno, line));
            }
        }
        return true;
    }

    void ConfigParser::iter_all_sections(std::function<void(std::string_view, const SectionValues&)> visit)
    {
        for (const auto& item : _config)
            visit(item.first, item.second);
    }

    bool ConfigParser::visit_section(const char* name, std::function<bool(const SectionValues& sect)> visit) const
    {
        // m_Config is effectively:
        // unordered_map< string, unordered_multimap< string, string  >>
        // in human terms: a map of of sections
        //                 where a section is a multimap of k:v pairs
        auto itr = _config.find(name);
        if (itr == _config.end())
            return false;
        return visit(itr->second);
    }

    void ConfigParser::add_override(fs::path fpath, std::string section, std::string key, std::string value)
    {
        auto& data = _overrides[fpath];
        data[section].emplace(key, value);
    }

    void ConfigParser::save()
    {
        // write overrides
        for (const auto& [fname, overrides] : _overrides)
        {
            std::ofstream ofs(fname);
            for (const auto& [section, values] : overrides)
            {
                ofs << std::endl << "[" << section << "]" << std::endl;
                for (const auto& [key, value] : values)
                {
                    ofs << key << "=" << value << std::endl;
                }
            }
        }
        _overrides.clear();
    }

    void ConfigParser::save_new() const
    {
        if (not _overrides.empty())
        {
            throw std::invalid_argument("Override specified when attempting new .ini save");
        }
        if (_config.empty())
        {
            throw std::invalid_argument("New config not loaded when attempting new .ini save");
        }
        if (_filename.empty())
        {
            throw std::invalid_argument("New config cannot be saved with filepath specified");
        }

        std::ofstream ofs(_filename);
        for (const auto& [section, values] : _config)
        {
            ofs << std::endl << "[" << section << "]" << std::endl;
            for (const auto& [key, value] : values)
            {
                ofs << key << "=" << value << std::endl;
            }
        }
    }

}  // namespace llarp
