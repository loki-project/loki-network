#pragma once

// #include <llarp/net/net.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/buffer.hpp>

namespace llarp
{
    struct alignas(uint64_t) session_tag
    {
        static constexpr size_t SIZE{8};

        std::array<uint8_t, SIZE> buf;

        session_tag() = default;

      private:
        session_tag(uint8_t protocol);

      public:
        static session_tag make(uint8_t protocol);

        std::tuple<bool, bool> proto_bits() const;

        void read(std::string_view buf);

        std::string_view view() const;
        uspan span() const;

        auto operator<=>(const session_tag& other) const { return buf <=> other.buf; }
        bool operator==(const session_tag& other) const { return (*this <=> other) == 0; }

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::session_tag>
    {
        size_t operator()(const llarp::session_tag& tag) const noexcept
        {
            return std::hash<std::string_view>{}(tag.view());
        }
    };
}  // namespace std
