#pragma once
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>

#include <ws2tcpip.h>
#include <wspiapi.h>
// because this shit is not defined for Windows NT reeeee
#ifdef __cplusplus
extern "C"
{
#endif
#if _WIN32_WINNT < 0x600
    const char* inet_ntop(int af, const void* src, char* dst, size_t size);
    int inet_pton(int af, const char* src, void* dst);
#endif
#ifdef __cplusplus
}
#endif
typedef unsigned short in_port_t;
typedef unsigned int in_addr_t;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <sys/types.h>

bool llarp_getifaddr(const char* ifname, int af, struct sockaddr* addr);
