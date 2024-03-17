#include "definition.hpp"

#include <llarp/util/logging.hpp>

#include <cassert>
#include <iterator>
#include <stdexcept>

namespace llarp
{
    static auto logcat = log::Cat("config.def");

    template <>
    bool OptionDefinition<bool>::from_string(const std::string& input)
    {
        if (input == "false" || input == "off" || input == "0" || input == "no")
            return false;
        if (input == "true" || input == "on" || input == "1" || input == "yes")
            return true;
        throw std::invalid_argument{fmt::format("{} is not a valid bool", input)};
    }

    ConfigDefinition& ConfigDefinition::define_option(std::unique_ptr<OptionDefinitionBase> def)
    {
        using namespace config;
        // If explicitly deprecated or is a {client,relay} option in a {relay,client} config then
        // add a dummy, warning option instead of this one.
        if (def->deprecated || (relay ? def->clientOnly : def->relay_only))
        {
            return define_option<std::string>(
                def->section,
                def->name,
                MultiValue,
                Hidden,
                [deprecated = def->deprecated, relay = relay, opt = "[" + def->section + "]:" + def->name](
                    std::string_view) {
                    log::warning(
                        logcat,
                        "*** WARNING: The config option {} {} and has been ignored",
                        opt,
                        (deprecated  ? " is deprecated"
                             : relay ? " is not valid in service node configuration files"
                                     : " is not valid in client configuration files"));
                });
        }

        auto [sectionItr, newSect] = definitions.try_emplace(def->section);
        if (newSect)
            section_ordering.push_back(def->section);
        auto& section = sectionItr->first;

        auto [it, added] = definitions[section].try_emplace(std::string{def->name}, std::move(def));
        if (!added)
            throw std::invalid_argument{fmt::format("definition for [{}]:{} already exists", def->section, def->name)};

        definition_ordering[section].push_back(it->first);

        if (!it->second->comments.empty())
            add_option_comments(section, it->first, std::move(it->second->comments));

        return *this;
    }

    ConfigDefinition& ConfigDefinition::add_config_value(
        std::string_view section, std::string_view name, std::string_view value)
    {
        // see if we have an undeclared handler to fall back to in case section or section:name is
        // absent
        auto undItr = undeclared_handlers.find(std::string(section));
        bool haveUndeclaredHandler = (undItr != undeclared_handlers.end());

        // get section, falling back to undeclared handler if needed
        auto secItr = definitions.find(std::string(section));
        if (secItr == definitions.end())
        {
            // fallback to undeclared handler if available
            if (not haveUndeclaredHandler)
                throw std::invalid_argument{fmt::format("unrecognized section [{}]", section)};
            auto& handler = undItr->second;
            handler(section, name, value);
            return *this;
        }

        // section was valid, get definition by name
        // fall back to undeclared handler if needed
        auto& sectionDefinitions = secItr->second;
        auto defItr = sectionDefinitions.find(std::string(name));
        if (defItr != sectionDefinitions.end())
        {
            std::unique_ptr<OptionDefinitionBase>& definition = defItr->second;
            definition->parse_value(std::string(value));
            return *this;
        }

        if (not haveUndeclaredHandler)
            throw std::invalid_argument{fmt::format("unrecognized option [{}]: {}", section, name)};

        auto& handler = undItr->second;
        handler(section, name, value);
        return *this;
    }

    void ConfigDefinition::add_undeclared_handler(const std::string& section, UndeclaredValueHandler handler)
    {
        auto itr = undeclared_handlers.find(section);
        if (itr != undeclared_handlers.end())
            throw std::logic_error{fmt::format("section {} already has a handler", section)};

        undeclared_handlers[section] = std::move(handler);
    }

    void ConfigDefinition::remove_undeclared_handler(const std::string& section)
    {
        auto itr = undeclared_handlers.find(section);
        if (itr != undeclared_handlers.end())
            undeclared_handlers.erase(itr);
    }

    void ConfigDefinition::validate_required_fields()
    {
        visit_sections([&](const std::string& section, const DefinitionMap&) {
            visit_definitions(section, [&](const std::string&, const std::unique_ptr<OptionDefinitionBase>& def) {
                if (def->required and def->get_number_found() < 1)
                {
                    throw std::invalid_argument{fmt::format("[{}]:{} is required but missing", section, def->name)};
                }

                // should be handled earlier in OptionDefinition::parse_value()
                assert(def->get_number_found() <= 1 or def->multi_valued);
            });
        });
    }

    void ConfigDefinition::accept_all_options()
    {
        visit_sections([this](const std::string& section, const DefinitionMap&) {
            visit_definitions(section, [](const std::string&, const std::unique_ptr<OptionDefinitionBase>& def) {
                def->try_accept();
            });
        });
    }

    void ConfigDefinition::add_section_comments(const std::string& section, std::vector<std::string> comments)
    {
        auto& sectionComments = section_comments[section];
        for (auto& c : comments)
            sectionComments.emplace_back(std::move(c));
    }

    void ConfigDefinition::add_option_comments(
        const std::string& section, const std::string& name, std::vector<std::string> comments)
    {
        auto& defComments = definition_comments[section][name];
        if (defComments.empty())
            defComments = std::move(comments);
        else
            defComments.insert(
                defComments.end(), std::make_move_iterator(comments.begin()), std::make_move_iterator(comments.end()));
    }

    std::string ConfigDefinition::generate_ini_config(bool useValues)
    {
        std::string ini;
        auto ini_append = std::back_inserter(ini);

        int sectionsVisited = 0;

        visit_sections([&](const std::string& section, const DefinitionMap&) {
            std::string sect_str;
            auto sect_append = std::back_inserter(sect_str);

            visit_definitions(section, [&](const std::string& name, const std::unique_ptr<OptionDefinitionBase>& def) {
                bool has_comment = false;
                // TODO: as above, this will create empty objects
                // TODO: as above (but more important): this won't handle definitions with no
                // entries
                //       (i.e. those handled by UndeclaredValueHandler's)
                for (const std::string& comment : definition_comments[section][name])
                {
                    fmt::format_to(sect_append, "\n# {}", comment);
                    has_comment = true;
                }

                if (useValues and def->get_number_found() > 0)
                {
                    for (const auto& val : def->values_as_string())
                        fmt::format_to(sect_append, "\n{}={}", name, val);
                    *sect_append = '\n';
                }
                else if (not def->hidden)
                {
                    if (auto defaults = def->default_values_as_string(); not defaults.empty())
                        for (const auto& val : defaults)
                            fmt::format_to(sect_append, "\n{}{}={}", def->required ? "" : "#", name, val);
                    else
                        // We have no defaults so we append it as "#opt-name=" so that we show
                        // the option name, and make it simple to uncomment and edit to the
                        // desired value.
                        fmt::format_to(sect_append, "\n#{}=", name);
                    *sect_append = '\n';
                }
                else if (has_comment)
                    *sect_append = '\n';
            });

            if (sect_str.empty())
                return;  // Skip sections with no options

            if (sectionsVisited > 0)
                ini += "\n\n";

            fmt::format_to(ini_append, "[{}]\n", section);

            // TODO: this will create empty objects as a side effect of map's operator[]
            // TODO: this also won't handle sections which have no definition
            for (const std::string& comment : section_comments[section])
            {
                fmt::format_to(ini_append, "# {}\n", comment);
            }
            ini += "\n";
            ini += sect_str;

            sectionsVisited++;
        });

        return ini;
    }

    const std::unique_ptr<OptionDefinitionBase>& ConfigDefinition::lookup_definition_or_throw(
        std::string_view section, std::string_view name) const
    {
        const auto sectionItr = definitions.find(std::string(section));
        if (sectionItr == definitions.end())
            throw std::invalid_argument{fmt::format("No config section [{}]", section)};

        auto& sectionDefinitions = sectionItr->second;
        const auto definitionItr = sectionDefinitions.find(std::string(name));
        if (definitionItr == sectionDefinitions.end())
            throw std::invalid_argument{fmt::format("No config item {} within section {}", name, section)};

        return definitionItr->second;
    }

    std::unique_ptr<OptionDefinitionBase>& ConfigDefinition::lookup_definition_or_throw(
        std::string_view section, std::string_view name)
    {
        return const_cast<std::unique_ptr<OptionDefinitionBase>&>(
            const_cast<const ConfigDefinition*>(this)->lookup_definition_or_throw(section, name));
    }

    void ConfigDefinition::visit_sections(SectionVisitor visitor) const
    {
        for (const std::string& section : section_ordering)
        {
            const auto itr = definitions.find(section);
            assert(itr != definitions.end());
            visitor(section, itr->second);
        }
    };
    void ConfigDefinition::visit_definitions(const std::string& section, DefVisitor visitor) const
    {
        const auto& defs = definitions.at(section);
        const auto& defOrdering = definition_ordering.at(section);
        for (const std::string& name : defOrdering)
        {
            const auto itr = defs.find(name);
            assert(itr != defs.end());
            visitor(name, itr->second);
        }
    };

}  // namespace llarp
