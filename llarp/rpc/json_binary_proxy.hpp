#pragma once

#include <nlohmann/json.hpp>

#include <string_view>
#include <unordered_set>

namespace llarp::rpc
{

    // Binary types that we support for rpc input/output.  For json, these must be specified as hex
    // or base64; for bt-encoded requests these can be accepted as binary, hex, or base64.
    template <typename T>
    inline constexpr bool json_is_binary = false;

    template <typename T>
    inline constexpr bool json_is_binary_container = false;
    template <typename T>
    inline constexpr bool json_is_binary_container<std::vector<T>> = json_is_binary<T>;
    template <typename T>
    inline constexpr bool json_is_binary_container<std::unordered_set<T>> = json_is_binary<T>;

    // De-referencing wrappers around the above:
    template <typename T>
    inline constexpr bool json_is_binary<const T&> = json_is_binary<T>;
    template <typename T>
    inline constexpr bool json_is_binary<T&&> = json_is_binary<T>;
    template <typename T>
    inline constexpr bool json_is_binary_container<const T&> = json_is_binary_container<T>;
    template <typename T>
    inline constexpr bool json_is_binary_container<T&&> = json_is_binary_container<T>;

    void load_binary_parameter_impl(std::string_view bytes, size_t raw_size, bool allow_raw, uint8_t* val_data);

    // Loads a binary value from a string_view which may contain hex, base64, and (optionally) raw
    // bytes.
    template <typename T, typename = std::enable_if_t<json_is_binary<T>>>
    void load_binary_parameter(std::string_view bytes, bool allow_raw, T& val)
    {
        load_binary_parameter_impl(bytes, sizeof(T), allow_raw, reinterpret_cast<uint8_t*>(&val));
    }

    // Wrapper around a nlohmann::json that assigns a binary value either as binary (for
    // bt-encoding); or as hex or base64 (for json-encoding).
    class json_binary_proxy
    {
      public:
        nlohmann::json& e;
        enum class fmt
        {
            bt,
            hex,
            base64
        } format;
        explicit json_binary_proxy(nlohmann::json& elem, fmt format) : e{elem}, format{format} {}
        json_binary_proxy() = delete;

        json_binary_proxy(const json_binary_proxy&) = default;
        json_binary_proxy(json_binary_proxy&&) = default;

        /// Dereferencing a proxy element accesses the underlying nlohmann::json
        nlohmann::json& operator*() { return e; }
        nlohmann::json* operator->() { return &e; }

        /// Descends into the json object, returning a new binary value proxy around the child
        /// element.
        template <typename T>
        json_binary_proxy operator[](T&& key)
        {
            return json_binary_proxy{e[std::forward<T>(key)], format};
        }

        /// Returns a binary value proxy around the first/last element (requires an underlying list)
        json_binary_proxy front() { return json_binary_proxy{e.front(), format}; }
        json_binary_proxy back() { return json_binary_proxy{e.back(), format}; }

        /// Assigns binary data from a string_view/string/etc.
        nlohmann::json& operator=(std::string_view binary_data);

        /// Assigns binary data from a string_view over a 1-byte, non-char type (e.g. unsigned char
        /// or uint8_t).
        template <typename Char, std::enable_if_t<sizeof(Char) == 1 && !std::is_same_v<Char, char>, int> = 0>
        nlohmann::json& operator=(std::basic_string_view<Char> binary_data)
        {
            return *this = std::string_view{reinterpret_cast<const char*>(binary_data.data()), binary_data.size()};
        }

        /// Takes a trivial, no-padding data structure (e.g. a crypto::hash) as the value and dumps
        /// its contents as the binary value.
        template <typename T, std::enable_if_t<json_is_binary<T>, int> = 0>
        nlohmann::json& operator=(const T& val)
        {
            return *this = std::string_view{reinterpret_cast<const char*>(&val), sizeof(val)};
        }

        /// Takes a vector of some json_binary_proxy-assignable type and builds an array by
        /// assigning each one into a new array of binary values.
        template <typename T, std::enable_if_t<json_is_binary_container<T>, int> = 0>
        nlohmann::json& operator=(const T& vals)
        {
            auto a = nlohmann::json::array();
            for (auto& val : vals)
                json_binary_proxy{a.emplace_back(), format} = val;
            return e = std::move(a);
        }
        /// Emplaces a new nlohman::json to the end of an underlying list and returns a
        /// json_binary_proxy wrapping it.
        ///
        /// Example:
        ///
        ///     auto child = wrappedelem.emplace_back({"key1": 1}, {"key2": 2});
        ///     child["binary-key"] = some_binary_thing;
        template <typename... Args>
        json_binary_proxy emplace_back(Args&&... args)
        {
            return json_binary_proxy{e.emplace_back(std::forward<Args>(args)...), format};
        }

        /// Adds an element to an underlying list, then copies or moves the given argument onto it
        /// via json_binary_proxy assignment.
        template <typename T>
        void push_back(T&& val)
        {
            emplace_back() = std::forward<T>(val);
        }
    };

}  // namespace llarp::rpc
