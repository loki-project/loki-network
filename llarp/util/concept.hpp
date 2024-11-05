#pragma once

#include <oxen/quic/format.hpp>

namespace llarp::concepts
{
    // Types can opt-in to being fmt-formattable by ensuring they have a ::to_string() method defined
    template <typename T>
    concept to_string_formattable = oxen::quic::concepts::ToStringFormattable<T>;

    template <typename T, typename U = std::remove_cvref_t<T>>
    concept forward_iterable = std::forward_iterator<typename U::iterator>;

#ifndef __cpp_lib_is_scoped_enum
    template <typename T>
        struct is_scoped_enum_st : std::bool_constant < requires
    {
        requires std::is_enum_v<T>;
        requires not std::is_convertible_v<T, std::underlying_type_t<T>>;
    } > {};

    template <typename T>
    inline constexpr bool is_scoped_enum_v = is_scoped_enum_st<T>::value;
#endif

    template <typename T>
    concept is_scoped_enum =
#ifdef __cpp_lib_is_scoped_enum
        std::is_scoped_enum_v<T>;
#else
        is_scoped_enum_v<T>;
#endif

}  // namespace llarp::concepts
