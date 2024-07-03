#pragma once

#include "buffer.hpp"

#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#ifndef _MSC_VER
#include <dirent.h>
#endif

#include <oxenc/common.h>

namespace fs = std::filesystem;

namespace llarp::util
{
    template <oxenc::basic_char T>
    std::streampos file_reader_impl(const fs::path& filename, std::basic_ifstream<T>& in)
    {
        in.exceptions(std::basic_ifstream<T>::failbit | std::basic_ifstream<T>::badbit);
        in.open(filename, std::ios::binary | std::ios::in);
        in.seekg(0, std::ios::end);
        auto size = in.tellg();
        in.seekg(0, std::ios::beg);
        return size;
    }

    template <oxenc::basic_char T>
    std::basic_string<T> file_to_string(const fs::path& filename)
    {
        std::basic_ifstream<T> in;
        std::basic_string<T> contents;
        auto size = file_reader_impl(filename, in);
        in.read(contents.data(), size);
        return contents;
    }

    /// Reads a binary file from disk into a string.  Throws on error.
    std::string file_to_string(const fs::path& filename);

    /// Reads a binary file from disk directly into a buffer.  Throws a std::length_error if the
    /// file is bigger than the buffer.  Returns the bytes copied on success.
    size_t file_to_buffer(const fs::path& filename, char* buffer, size_t buffer_size);

    /// Same, but for some non-char but single-byte char type (e.g. uint8_t, std::byte, unsigned
    /// char).
    template <typename Char, std::enable_if_t<sizeof(Char) == 1 and not std::is_same_v<Char, char>, int> = 1>
    size_t file_to_buffer(const fs::path& filename, Char* buffer, size_t buffer_size)
    {
        return file_to_buffer(filename, reinterpret_cast<char*>(buffer), buffer_size);
    }

    /// Dumps binary string contents to disk. The file is overwritten if it already exists.  Throws
    /// on error.
    void buffer_to_file(const fs::path& filename, std::string_view contents);

    /// Same as above, but works via char-like buffer
    template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
    void buffer_to_file(const fs::path& filename, const Char* buffer, size_t buffer_size)
    {
        return buffer_to_file(filename, std::string_view{reinterpret_cast<const char*>(buffer), buffer_size});
    }

    struct FileHash
    {
        size_t operator()(const fs::path& f) const
        {
            std::hash<std::string> h;
            return h(f.string());
        }
    };

    using error_code_t = std::error_code;

    /// Ensure that a file exists and has correct permissions
    /// return any error code or success
    error_code_t EnsurePrivateFile(fs::path pathname);

    /// open a stream to a file and ensure it exists before open
    /// sets any permissions on creation
    template <typename T>
    std::optional<T> OpenFileStream(fs::path pathname, std::ios::openmode mode)
    {
        if (EnsurePrivateFile(pathname))
            return {};
        return std::make_optional<T>(pathname, mode);
    }

}  // namespace llarp::util
