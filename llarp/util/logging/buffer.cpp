#include "buffer.hpp"

namespace llarp
{
    std::string buffer_printer::to_string() const
    {
        auto& b = buf;
        std::string out;
        auto ins = std::back_inserter(out);
        fmt::format_to(ins, "Buffer[{}/{:#x} bytes]:", b.size(), b.size());

        for (size_t i = 0; i < b.size(); i += 32)
        {
            fmt::format_to(ins, "\n{:04x} ", i);

            size_t stop = std::min(b.size(), i + 32);
            for (size_t j = 0; j < 32; j++)
            {
                auto k = i + j;
                if (j % 4 == 0)
                    out.push_back(' ');
                if (k >= stop)
                    out.append("  ");
                else
                    fmt::format_to(ins, "{:02x}", std::to_integer<uint_fast16_t>(b[k]));
            }
            out.append(u8"  ┃");
            for (size_t j = i; j < stop; j++)
            {
                auto c = std::to_integer<char>(b[j]);
                if (c == 0x00)
                    out.append(u8"∅");
                else if (c < 0x20 || c > 0x7e)
                    out.append(u8"·");
                else
                    out.push_back(c);
            }
            out.append(u8"┃");
        }
        return out;
    }
}  // namespace llarp
