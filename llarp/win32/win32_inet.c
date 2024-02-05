#if defined(__MINGW32__) && !defined(_WIN64)
/*
 * Contains routines missing from WS2_32.DLL until 2006, if yer using
 * Microsoft C/C++, then this code is irrelevant, as the official
 * Platform SDK already links against these routines in the correct
 * libraries.
 *
 * -despair86 30/07/18
 */

// these need to be in a specific order
#include <llarp/net/net.h>

#include <windows.h>

#include <assert.h>
#include <iphlpapi.h>
#include <stdbool.h>

const char* inet_ntop(int af, const void* src, char* dst, size_t size)
{
    int address_length;
    DWORD string_length = size;
    struct sockaddr_storage sa;
    struct sockaddr_in* sin = (struct sockaddr_in*)&sa;
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&sa;

    memset(&sa, 0, sizeof(sa));
    switch (af)
    {
        case AF_INET:
            address_length = sizeof(struct sockaddr_in);
            sin->sin_family = af;
            memcpy(&sin->sin_addr, src, sizeof(struct in_addr));
            break;

        case AF_INET6:
            address_length = sizeof(struct sockaddr_in6);
            sin6->sin6_family = af;
            memcpy(&sin6->sin6_addr, src, sizeof(struct in6_addr));
            break;

        default:
            return NULL;
    }

    if (WSAAddressto_string((LPSOCKADDR)&sa, address_length, NULL, dst, &string_length) == 0)
    {
        return dst;
    }

    return NULL;
}

int inet_pton(int af, const char* src, void* dst)
{
    int address_length;
    struct sockaddr_storage sa;
    struct sockaddr_in* sin = (struct sockaddr_in*)&sa;
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&sa;

    switch (af)
    {
        case AF_INET:
            address_length = sizeof(struct sockaddr_in);
            break;

        case AF_INET6:
            address_length = sizeof(struct sockaddr_in6);
            break;

        default:
            return -1;
    }

    if (WSAStringToAddress((LPTSTR)src, af, NULL, (LPSOCKADDR)&sa, &address_length) == 0)
    {
        switch (af)
        {
            case AF_INET:
                memcpy(dst, &sin->sin_addr, sizeof(struct in_addr));
                break;

            case AF_INET6:
                memcpy(dst, &sin6->sin6_addr, sizeof(struct in6_addr));
                break;
        }
        return 1;
    }

    return 0;
}

#endif
