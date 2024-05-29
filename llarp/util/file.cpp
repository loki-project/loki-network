#include "file.hpp"

#include "formattable.hpp"
#include "logging.hpp"

#include <fcntl.h>

#include <fstream>
#include <ios>
#include <stdexcept>
#include <system_error>

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace llarp::util
{
    static auto logcat = log::Cat("util.file");

    static std::streampos file_reader_impl(const fs::path& filename, std::ifstream& in)
    {
        in.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        in.open(filename, std::ios::binary | std::ios::in);
        in.seekg(0, std::ios::end);
        auto size = in.tellg();
        in.seekg(0, std::ios::beg);
        return size;
    }

    std::string file_to_string(const fs::path& filename)
    {
        std::ifstream in;
        std::string contents;
        auto size = file_reader_impl(filename, in);
        contents.resize(size);
        in.read(contents.data(), size);
        return contents;
    }

    size_t file_to_buffer(const fs::path& filename, char* buffer, size_t buffer_size)
    {
        std::ifstream in;
        auto size = file_reader_impl(filename, in);
        if (static_cast<size_t>(size) > buffer_size)
            throw std::length_error{"file is too large for buffer"};
        in.read(buffer, size);
        return size;
    }

    void buffer_to_file(const fs::path& filename, std::string_view contents)
    {
        std::ofstream out;
        out.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        out.open(filename, std::ios::binary | std::ios::out | std::ios::trunc);
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }

    static std::error_code errno_error()
    {
        int e = errno;
        errno = 0;
        return std::make_error_code(static_cast<std::errc>(e));
    }

    error_code_t EnsurePrivateFile(fs::path pathname)
    {
        errno = 0;
        error_code_t ec = errno_error();
        const auto str = pathname.string();
        if (fs::exists(pathname, ec))  // file exists
        {
            auto st = fs::status(pathname);
            auto perms = st.permissions();
            if ((perms & fs::perms::others_exec) != fs::perms::none)
                perms = perms ^ fs::perms::others_exec;
            if ((perms & fs::perms::others_write) != fs::perms::none)
                perms = perms ^ fs::perms::others_write;
            if ((perms & fs::perms::others_write) != fs::perms::none)
                perms = perms ^ fs::perms::others_write;
            if ((perms & fs::perms::group_read) != fs::perms::none)
                perms = perms ^ fs::perms::group_read;
            if ((perms & fs::perms::others_read) != fs::perms::none)
                perms = perms ^ fs::perms::others_read;
            if ((perms & fs::perms::owner_exec) != fs::perms::none)
                perms = perms ^ fs::perms::owner_exec;

            fs::permissions(pathname, perms, ec);
            if (ec)
                log::error(logcat, "failed to set permissions on {}", pathname);
        }
        else  // file is not there
        {
            errno = 0;
            int fd = ::open(str.c_str(), O_RDWR | O_CREAT, 0600);
            ec = errno_error();
            if (fd != -1)
            {
                ::close(fd);
            }
        }

#ifndef WIN32
        if (ec)
            log::error(logcat, "failed to ensure {}: {}", str, ec.message());
        return ec;
#else
        return {};
#endif
    }

}  // namespace llarp::util
