#pragma once

#include <llarp/util/fs.hpp>
#include <llarp/util/str.hpp>

#include <fmt/core.h>

#include <cassert>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace llarp
{
    namespace config
    {
        namespace flag
        {
            // Base class for the following option flag types
            struct opt
            {};

            struct REQUIRED : opt
            {};
            struct HIDDEN : opt
            {};
            struct MULTIVALUE : opt
            {};
            struct RELAYONLY : opt
            {};
            struct CLIENTONLY : opt
            {};
            struct DEPRECATED : opt
            {};
        }  // namespace flag

        /// Value to pass for an OptionDefinition to indicate that the option is required
        inline constexpr flag::REQUIRED Required{};
        /// Value to pass for an OptionDefinition to indicate that the option should be hidden from
        /// the generate config file if it is unset (and has no comment).  Typically for deprecated,
        /// renamed options that still do something, and for internal dev options that aren't
        /// usefully exposed. (For do-nothing deprecated options use Deprecated instead).
        inline constexpr flag::HIDDEN Hidden{};
        /// Value to pass for an OptionDefinition to indicate that the option takes multiple values
        inline constexpr flag::MULTIVALUE MultiValue{};
        /// Value to pass for an option that should only be set for relay configs. If found in a
        /// client config it be ignored (but will produce a warning).
        inline constexpr flag::RELAYONLY RelayOnly{};
        /// Value to pass for an option that should only be set for client configs. If found in a
        /// relay config it will be ignored (but will produce a warning).
        inline constexpr flag::CLIENTONLY ClientOnly{};
        /// Value to pass for an option that is deprecated and does nothing and should be ignored
        /// (with a deprecation warning) if specified.  Note that Deprecated implies Hidden, and
        /// that {client,relay}-only options in a {relay,client} config are also considered
        /// Deprecated.
        inline constexpr flag::DEPRECATED Deprecated{};

        /// Wrapper to specify a default value to an OptionDefinition
        template <typename T>
        struct Default
        {
            T val;
            constexpr explicit Default(T val) : val{std::move(val)}
            {}
        };

        /// Adds one or more comment lines to the option definition.
        struct Comment
        {
            std::vector<std::string> comments;
            explicit Comment(std::initializer_list<std::string> comments) : comments{std::move(comments)}
            {}
        };

        /// A convenience function that returns an acceptor which assigns to a reference.
        ///
        /// Note that this holds on to the reference; it must only be used when this is safe to do.
        /// In particular, a reference to a local variable may be problematic.
        template <typename T>
        auto assignment_acceptor(T& ref)
        {
            return [&ref](T arg) { ref = std::move(arg); };
        }

        // C++20 backport:
        template <typename T>
        using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

        template <typename T>
        constexpr bool is_default = false;
        template <typename T>
        constexpr bool is_default<Default<T>> = true;
        template <typename U>
        constexpr bool is_default<U&> = is_default<remove_cvref_t<U>>;

        template <typename T>
        constexpr bool is_default_array = false;
        template <typename T, size_t N>
        constexpr bool is_default_array<std::array<Default<T>, N>> = true;
        template <typename U>
        constexpr bool is_default_array<U&> = is_default_array<remove_cvref_t<U>>;

        template <typename T, typename Option>
        constexpr bool is_option =
            std::is_base_of_v<flag::opt, remove_cvref_t<Option>> or std::is_same_v<Comment, Option>
            or is_default<Option> or is_default_array<Option> or std::is_invocable_v<remove_cvref_t<Option>, T>;
    }  // namespace config

    /// A base class for specifying config options and their constraints. The basic to/from string
    /// type functions are provided pure-virtual. The type-aware implementations which implement
    /// these functions are templated classes. One reason for providing a non-templated base class
    /// is so that they can all be mixed into the same containers (albiet as pointers).
    struct OptionDefinitionBase
    {
        template <typename... T>
        OptionDefinitionBase(std::string section_, std::string name_, const T&...)
            : section(std::move(section_)),
              name(std::move(name_)),
              required{(std::is_same_v<T, config::flag::REQUIRED> || ...)},
              multi_valued{(std::is_same_v<T, config::flag::MULTIVALUE> || ...)},
              deprecated{(std::is_same_v<T, config::flag::DEPRECATED> || ...)},
              hidden{deprecated || (std::is_same_v<T, config::flag::HIDDEN> || ...)},
              relay_only{(std::is_same_v<T, config::flag::RELAYONLY> || ...)},
              clientOnly{(std::is_same_v<T, config::flag::CLIENTONLY> || ...)}
        {}

        virtual ~OptionDefinitionBase() = default;

        /// Subclasses should provide their default value as a string
        ///
        /// @return the option's default value represented as a string
        virtual std::vector<std::string> default_values_as_string() = 0;

        /// Subclasses should parse and store the provided input
        ///
        /// @param input is the string input to interpret
        virtual void parse_value(const std::string& input) = 0;

        /// Subclasses should provide the number of values found.
        ///
        /// @return number of values found
        virtual size_t get_number_found() const = 0;

        /// Subclasess should write their parsed values as strings.
        ///
        /// @return the option's value(s) as strings
        virtual std::vector<std::string> values_as_string() = 0;

        /// Subclassess should call their acceptor, if present. See OptionDefinition for more
        /// details.
        ///
        /// @throws if the acceptor throws or the option is required but missing
        virtual void try_accept() const = 0;

        std::string section;
        std::string name;
        bool required = false;
        bool multi_valued = false;
        bool deprecated = false;
        bool hidden = false;
        bool relay_only = false;
        bool clientOnly = false;
        // Temporarily holds comments given during construction until the option is actually added
        // to the owning ConfigDefinition.
        std::vector<std::string> comments;
    };

    /// The primary type-aware implementation of OptionDefinitionBase, this templated class allows
    /// for implementations which can use fmt::format for conversion to string and
    /// std::istringstream for input from string.
    ///
    /// Note that types (T) used as template parameters here must be used verbatim when calling
    /// ConfigDefinition::getConfigValue(). Similar types such as uint32_t and int32_t cannot be
    /// mixed.
    template <typename T>
    struct OptionDefinition : public OptionDefinitionBase
    {
        /// Constructor. Arguments are passed directly to OptionDefinitionBase.
        ///
        /// @param defaultValue_ is used in the following situations:
        /// 1) as the return value for getValue() if there is no parsed value and required==false
        /// 2) as the output in default_values_as_string(), used to generate config files
        /// 3) as the output in valueAsString(), used to generate config files
        ///
        /// @param opts - 0 or more of config::Required, config::Hidden, config::Default{...}, etc.
        /// tagged options or an invocable acceptor validate and internalize input (e.g. copy it for
        /// runtime use). The acceptor should throw an exception with a useful message if it is not
        /// acceptable.  Parameters may be passed in any order.
        template <typename... Options, std::enable_if_t<(config::is_option<T, Options> && ...), int> = 0>
        OptionDefinition(std::string section_, std::string name_, Options&&... opts)
            : OptionDefinitionBase(section_, name_, opts...)
        {
            constexpr bool has_default = ((config::is_default_array<Options> || config::is_default<Options>) || ...);
            constexpr bool has_required =
                (std::is_same_v<config::remove_cvref_t<Options>, config::flag::REQUIRED> || ...);
            constexpr bool has_hidden = (std::is_same_v<config::remove_cvref_t<Options>, config::flag::HIDDEN> || ...);
            static_assert(not(has_default and has_required), "Default{...} and Required are mutually exclusive");
            static_assert(not(has_hidden and has_required), "Hidden and Required are mutually exclusive");

            (extract_default(std::forward<Options>(opts)), ...);
            (extract_acceptor(std::forward<Options>(opts)), ...);
            (extract_comments(std::forward<Options>(opts)), ...);
        }

        /// Extracts a default value from an config::Default<U> or an array of defaults (for
        /// multi-valued options with multi-value default); ignores anything else.
        template <typename U>
        void extract_default(U&& defaultValue_)
        {
            if constexpr (config::is_default_array<U>)
            {
                if (!multi_valued)
                    throw std::logic_error{"Array config defaults require multiValue mode"};

                default_values.clear();
                default_values.reserve(defaultValue_.size());
                for (const auto& def : defaultValue_)
                    default_values.push_back(def.val);
            }
            else if constexpr (config::is_default<U>)
            {
                static_assert(
                    std::is_convertible_v<decltype(std::forward<U>(defaultValue_).val), T>,
                    "Cannot convert given llarp::config::Default to the required value type");
                default_values = {std::forward<U>(defaultValue_).val};
            }
        }

        /// Extracts an acceptor (i.e. something callable with a `T`) from options; ignores anything
        /// that isn't callable.
        template <typename U>
        void extract_acceptor(U&& acceptor_)
        {
            if constexpr (std::is_invocable_v<U, T>)
                acceptor = std::forward<U>(acceptor_);
        }

        /// Extracts option Comments and forwards them addOptionComments.
        template <typename U>
        void extract_comments(U&& comment)
        {
            if constexpr (std::is_same_v<config::remove_cvref_t<U>, config::Comment>)
                comments = std::forward<U>(comment).comments;
        }

        /// Returns the first parsed value, if available. Otherwise, provides the (first) default
        /// value if the option is not required. Otherwise, returns an empty optional.
        ///
        /// @return an optional with the parsed value, the (first) default value, or no value.
        std::optional<T> get_value() const
        {
            if (parsed_values.empty())
            {
                if (required || default_values.empty())
                    return std::nullopt;
                return default_values.front();
            }
            return parsed_values.front();
        }

        /// Returns the number of values found.
        ///
        /// @return number of values found
        size_t get_number_found() const override
        {
            return parsed_values.size();
        }

        std::vector<std::string> default_values_as_string() override
        {
            if (default_values.empty())
                return {};
            if constexpr (std::is_same_v<fs::path, T>)
                return {{default_values.front().u8string()}};
            else
            {
                std::vector<std::string> def_strs;
                def_strs.reserve(default_values.size());
                for (const auto& v : default_values)
                {
                    if constexpr (std::is_same_v<bool, T>)
                        def_strs.push_back(fmt::format("{}", (bool)v));
                    else
                        def_strs.push_back(fmt::format("{}", v));
                }
                return def_strs;
            }
        }

        void parse_value(const std::string& input) override
        {
            if (not multi_valued and parsed_values.size() > 0)
            {
                throw std::invalid_argument{fmt::format("duplicate value for {}", name)};
            }

            parsed_values.emplace_back(from_string(input));
        }

        T from_string(const std::string& input)
        {
            if constexpr (std::is_same_v<T, std::string>)
            {
                return input;
            }
            else
            {
                std::istringstream iss(input);
                T t;
                iss >> t;
                if (iss.fail())
                    throw std::invalid_argument{fmt::format("{} is not a valid {}", input, typeid(T).name())};
                return t;
            }
        }

        std::vector<std::string> values_as_string() override
        {
            if (parsed_values.empty())
                return {};
            std::vector<std::string> result;
            result.reserve(parsed_values.size());
            for (const auto& v : parsed_values)
            {
                if constexpr (std::is_same_v<bool, T>)
                    result.push_back(fmt::format("{}", (bool)v));
                else
                    result.push_back(fmt::format("{}", v));
            }
            return result;
        }

        /// Attempts to call the acceptor function, if present. This function may throw if the value
        /// is not acceptable. Additionally, try_accept should not be called if the option is
        /// required and no value has been provided.
        ///
        /// @throws if required and no value present or if the acceptor throws
        void try_accept() const override
        {
            if (required and parsed_values.empty())
            {
                throw std::runtime_error{fmt::format(
                    "cannot call try_accept() on [{}]:{} when required but no value available", section, name)};
            }

            if (acceptor)
            {
                if (multi_valued)
                {
                    // add default value in multi value mode
                    if (parsed_values.empty() and not default_values.empty())
                        for (const auto& v : default_values)
                            acceptor(v);

                    for (auto value : parsed_values)
                    {
                        acceptor(value);
                    }
                }
                else
                {
                    auto maybe = get_value();
                    if (maybe)
                        acceptor(*maybe);
                }
            }
        }

        std::vector<T> default_values;
        std::vector<T> parsed_values;
        std::function<void(T)> acceptor;
    };

    /// Specialization for bool types. We don't want to use stringstream parsing in this
    /// case because we want to accept "truthy" and "falsy" string values (e.g. "off" == false)
    template <>
    bool OptionDefinition<bool>::from_string(const std::string& input);

    using UndeclaredValueHandler =
        std::function<void(std::string_view section, std::string_view name, std::string_view value)>;

    // map of k:v pairs
    using DefinitionMap = std::unordered_map<std::string, std::unique_ptr<OptionDefinitionBase>>;

    // map of section-name to map-of-definitions
    using SectionMap = std::unordered_map<std::string, DefinitionMap>;

    /// A ConfigDefinition holds an ordered set of OptionDefinitions defining the allowable values
    /// and their constraints (specified through calls to defineOption()).
    ///
    /// The layout and grouping of the config options are modelled after the INI file format; each
    /// option has a name and is grouped under a section. Duplicate option names are allowed only if
    /// they exist in a different section. The ConfigDefinition can be serialized in the INI file
    /// format using the generateINIConfig() function.
    ///
    /// Configured values (e.g. those encountered when parsing a file) can be provided through calls
    /// to addConfigValue(). These take a std::string as a value, which is automatically parsed.
    ///
    /// The ConfigDefinition can be used to print out a full config string (or file), including
    /// fields with defaults and optionally fields which have a specified value (values provided
    /// through calls to addConfigValue()).
    struct ConfigDefinition
    {
        explicit ConfigDefinition(bool relay) : relay{relay}
        {}

        /// Specify the parameters and type of a configuration option. The parameters are members of
        /// OptionDefinitionBase; the type is inferred from OptionDefinition's template parameter T.
        ///
        /// This function should be called for every option that this Configuration supports, and
        /// should be done before any other interactions involving that option.
        ///
        /// @param def should be a unique_ptr to a valid subclass of OptionDefinitionBase
        /// @return `*this` for chaining calls
        /// @throws std::invalid_argument if the option already exists
        ConfigDefinition& define_option(std::unique_ptr<OptionDefinitionBase> def);

        /// Convenience function which calls defineOption with a OptionDefinition of the specified
        /// type and with parameters passed through to OptionDefinition's constructor.
        template <typename T, typename... Params>
        ConfigDefinition& define_option(Params&&... args)
        {
            return define_option(std::make_unique<OptionDefinition<T>>(std::forward<Params>(args)...));
        }

        /// Specify a config value for the given section and name. The value should be a valid
        /// string representing the type used by the option (e.g. the type provided when
        /// defineOption() was called).
        ///
        /// If the specified option doesn't exist, an exception will be thrown. Otherwise, the
        /// option's parse_value() will be invoked, and should throw an exception if the string
        /// can't be parsed.
        ///
        /// @param section is the section this value resides in
        /// @param name is the name of the value
        /// @return `*this` for chaining calls
        /// @throws if the option doesn't exist or the provided string isn't parseable
        ConfigDefinition& add_config_value(std::string_view section, std::string_view name, std::string_view value);

        /// Get a config value. If the value hasn't been provided but a default has, the default
        /// will be returned. If no value and no default is provided, an empty optional will be
        /// returned.
        ///
        /// The type T should exactly match that provided by the definition; it is not sufficient
        /// for one type to be a valid substitution for the other.
        ///
        /// @param section is the section this value resides in
        /// @param name is the name of the value
        /// @return an optional providing the configured value, the default, or empty
        /// @throws std::invalid_argument if there is no such config option or the wrong type T was
        //          provided
        template <typename T>
        std::optional<T> get_config_value(std::string_view section, std::string_view name)
        {
            std::unique_ptr<OptionDefinitionBase>& definition = lookup_definition_or_throw(section, name);

            auto derived = dynamic_cast<const OptionDefinition<T>*>(definition.get());
            if (not derived)
                throw std::invalid_argument{
                    fmt::format("{} is the incorrect type for [{}]:{}", typeid(T).name(), section, name)};

            return derived->getValue();
        }

        /// Add an "undeclared" handler for the given section. This is a handler that will be called
        /// whenever a k:v pair is found that doesn't match a provided definition.
        ///
        /// Any exception thrown by the handler will progagate back through the call to
        /// addConfigValue().
        ///
        /// @param section is the section for which any undeclared values will invoke the provided
        ///        handler
        /// @param handler
        /// @throws if there is already a handler for this section
        void add_undeclared_handler(const std::string& section, UndeclaredValueHandler handler);

        /// Removes an "undeclared" handler for the given section.
        ///
        /// @param section is the section which we want to remove the handler for
        void remove_undeclared_handler(const std::string& section);

        /// Validate that all required fields are present.
        ///
        /// @throws std::invalid_argument if configuration constraints are not met
        void validate_required_fields();

        /// Accept all options. This will call the acceptor (if present) on each option. Note that
        /// this should only be called if all required fields are present (that is,
        /// validateRequiredFields() has been or could be called without throwing).
        ///
        /// @throws if any option's acceptor throws
        void accept_all_options();

        /// validates and accept all parsed options
        inline void process()
        {
            validate_required_fields();
            accept_all_options();
        }

        /// Add comments for a given section. Comments are replayed in-order during config file
        /// generation. A proper comment prefix will automatically be applied, and the entire
        /// comment will otherwise be used verbatim (no automatic line separation, etc.).
        ///
        /// @param section
        /// @param comment
        void add_section_comments(const std::string& section, std::vector<std::string> comments);

        /// Add comments for a given option. Similar to addSectionComment, but applies to a specific
        /// [section]:name pair.
        ///
        /// @param section
        /// @param name
        /// @param comment
        void add_option_comments(
            const std::string& section, const std::string& name, std::vector<std::string> comments);

        /// Generate a config string from the current config definition, optionally using overridden
        /// values. The generated config will preserve insertion order of both sections and their
        /// definitions.
        ///
        /// Definitions which are required or have an overriden value (and useValues == true) will
        /// be written normally. Otherwise, they will be written commented-out in order to provide a
        /// complete documentation of the configuration file.
        ///
        /// @param useValues specifies whether we use specified values (e.g. those from calls to
        ///        addConfigValue()) or only definitions
        /// @return a string containing the config in INI format
        std::string generate_ini_config(bool useValues = false);

      private:
        // If true skip client-only options; if false skip relay-only options.
        bool relay;

        std::unique_ptr<OptionDefinitionBase>& lookup_definition_or_throw(
            std::string_view section, std::string_view name);
        const std::unique_ptr<OptionDefinitionBase>& lookup_definition_or_throw(
            std::string_view section, std::string_view name) const;

        using SectionVisitor = std::function<void(const std::string&, const DefinitionMap&)>;
        void visit_sections(SectionVisitor visitor) const;

        using DefVisitor = std::function<void(const std::string&, const std::unique_ptr<OptionDefinitionBase>&)>;
        void visit_definitions(const std::string& section, DefVisitor visitor) const;

        SectionMap definitions;

        std::unordered_map<std::string, UndeclaredValueHandler> undeclared_handlers;

        // track insertion order. the vector<string>s are ordered list of section/option names.
        std::vector<std::string> section_ordering;
        std::unordered_map<std::string, std::vector<std::string>> definition_ordering;

        // comments for config file generation
        using CommentList = std::vector<std::string>;
        using CommentsMap = std::unordered_map<std::string, CommentList>;
        CommentsMap section_comments;
        std::unordered_map<std::string, CommentsMap> definition_comments;
    };

}  // namespace llarp
