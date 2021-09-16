#pragma once

#include <windows.h>
#include <iphlpapi.h>
#include <io.h>
#include <fcntl.h>
#include <llarp/util/thread/queue.hpp>
#include <llarp/ev/vpn.hpp>

#include <fwpmu.h>

// DDK macros
#define CTL_CODE(DeviceType, Function, Method, Access) \
  (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define FILE_DEVICE_UNKNOWN 0x00000022
#define FILE_ANY_ACCESS 0x00000000
#define METHOD_BUFFERED 0

/* From OpenVPN tap driver, common.h */
#define TAP_CONTROL_CODE(request, method) \
  CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MAC TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION TAP_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU TAP_CONTROL_CODE(3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO TAP_CONTROL_CODE(4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE(5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ TAP_CONTROL_CODE(7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE TAP_CONTROL_CODE(8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT TAP_CONTROL_CODE(9, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN TAP_CONTROL_CODE(10, METHOD_BUFFERED)

/* Windows registry crap */
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef unsigned long IPADDR;

namespace llarp::vpn
{
  constexpr auto NETWORK_ADAPTERS =
      "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

  static char*
  reg_query(const char* key_name)
  {
    HKEY adapters, adapter;
    DWORD i, ret, len;
    char* deviceid = nullptr;
    DWORD sub_keys = 0;

    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(key_name), 0, KEY_READ, &adapters);
    if (ret != ERROR_SUCCESS)
    {
      return nullptr;
    }

    ret = RegQueryInfoKey(
        adapters, NULL, NULL, NULL, &sub_keys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (ret != ERROR_SUCCESS)
    {
      return nullptr;
    }

    if (sub_keys <= 0)
    {
      return nullptr;
    }

    /* Walk througt all adapters */
    for (i = 0; i < sub_keys; i++)
    {
      char new_key[MAX_KEY_LENGTH];
      char data[256];
      TCHAR key[MAX_KEY_LENGTH];
      DWORD keylen = MAX_KEY_LENGTH;

      /* Get the adapter key name */
      ret = RegEnumKeyEx(adapters, i, key, &keylen, NULL, NULL, NULL, NULL);
      if (ret != ERROR_SUCCESS)
      {
        continue;
      }

      /* Append it to NETWORK_ADAPTERS and open it */
      snprintf(new_key, sizeof new_key, "%s\\%s", key_name, key);
      ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(new_key), 0, KEY_READ, &adapter);
      if (ret != ERROR_SUCCESS)
      {
        continue;
      }

      /* Check its values */
      len = sizeof data;
      ret = RegQueryValueEx(adapter, "ComponentId", NULL, NULL, (LPBYTE)data, &len);
      if (ret != ERROR_SUCCESS)
      {
        /* This value doesn't exist in this adaptater tree */
        goto clean;
      }
      /* If its a tap adapter, its all good */
      if (strncmp(data, "tap0901", 7) == 0)
      {
        DWORD type;

        len = sizeof data;
        ret = RegQueryValueEx(adapter, "NetCfgInstanceId", NULL, &type, (LPBYTE)data, &len);
        if (ret != ERROR_SUCCESS)
        {
          goto clean;
        }
        deviceid = strdup(data);
        break;
      }
    clean:
      RegCloseKey(adapter);
    }
    RegCloseKey(adapters);
    return deviceid;
  }

  template <typename Visit>
  void
  ForEachWIN32Interface(Visit visit)
  {
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
    MIB_IPFORWARDTABLE* pIpForwardTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    pIpForwardTable = (MIB_IPFORWARDTABLE*)MALLOC(sizeof(MIB_IPFORWARDTABLE));
    if (pIpForwardTable == nullptr)
      return;

    if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
    {
      FREE(pIpForwardTable);
      pIpForwardTable = (MIB_IPFORWARDTABLE*)MALLOC(dwSize);
      if (pIpForwardTable == nullptr)
      {
        return;
      }
    }

    if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0)) == NO_ERROR)
    {
      for (int i = 0; i < (int)pIpForwardTable->dwNumEntries; i++)
      {
        visit(&pIpForwardTable->table[i]);
      }
    }
    FREE(pIpForwardTable);
#undef MALLOC
#undef FREE
  }

  std::optional<int>
  GetInterfaceIndex(huint32_t ip)
  {
    std::optional<int> ret = std::nullopt;
    ForEachWIN32Interface([&ret, n = ToNet(ip)](auto* iface) {
      if (ret.has_value())
        return;
      if (iface->dwForwardNextHop == n.n)
      {
        ret = iface->dwForwardIfIndex;
      }
    });
    return ret;
  }

  class Win32Interface final : public NetworkInterface
  {
    std::atomic<bool> m_Run;
    HANDLE m_Device, m_IOCP;
    std::vector<std::thread> m_Threads;
    thread::Queue<net::IPPacket> m_ReadQueue;

    InterfaceInfo m_Info;

    static std::wstring
    get_win_sys_path()
    {
      wchar_t win_sys_path[MAX_PATH] = {0};
      const wchar_t* default_sys_path = L"C:\\Windows\\system32";

      if (!GetSystemDirectoryW(win_sys_path, _countof(win_sys_path)))
      {
        wcsncpy(win_sys_path, default_sys_path, _countof(win_sys_path));
        win_sys_path[_countof(win_sys_path) - 1] = L'\0';
      }
      return win_sys_path;
    }

    static std::string
    NetSHCommand()
    {
      std::wstring wcmd = get_win_sys_path() + L"\\netsh.exe";

      using convert_type = std::codecvt_utf8<wchar_t>;
      std::wstring_convert<convert_type, wchar_t> converter;
      return converter.to_bytes(wcmd);
    }

    static void
    NetSH(std::string commands)
    {
      commands = NetSHCommand() + " interface IPv6 " + commands;
      LogInfo(commands);
      ::system(commands.c_str());
    }

   public:
    static std::string
    RouteCommand()
    {
      std::wstring wcmd = get_win_sys_path() + L"\\route.exe";

      using convert_type = std::codecvt_utf8<wchar_t>;
      std::wstring_convert<convert_type, wchar_t> converter;
      return converter.to_bytes(wcmd);
    }

    Win32Interface(InterfaceInfo info) : m_ReadQueue{1024}, m_Info{std::move(info)}
    {
      DWORD len;

      const auto device_id = reg_query(NETWORK_ADAPTERS);
      if (device_id == nullptr)
      {
        LogError("cannot query registry");
        throw std::invalid_argument{"cannot query registery"};
      }
      std::stringstream ss;
      ss << "\\\\.\\Global\\" << device_id << ".tap";
      const auto fname = ss.str();
      m_Device = CreateFile(
          fname.c_str(),
          GENERIC_WRITE | GENERIC_READ,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          0,
          OPEN_EXISTING,
          FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
          0);
      if (m_Device == INVALID_HANDLE_VALUE)
      {
        LogError("failed to open device");
        throw std::invalid_argument{"cannot open " + fname};
      }

      LogInfo("putting interface up...");
      ULONG flag = 1;
      // put the interface up
      if (not DeviceIoControl(
              m_Device,
              TAP_IOCTL_SET_MEDIA_STATUS,
              &flag,
              sizeof(flag),
              &flag,
              sizeof(flag),
              &len,
              nullptr))
      {
        LogError("cannot up interface up");
        throw std::invalid_argument{"cannot put interface up"};
      }

      LogInfo("setting addresses");
      huint32_t ip{};
      // set ipv4 addresses
      for (const auto& ifaddr : m_Info.addrs)
      {
        if (ifaddr.fam == AF_INET)
        {
          IPADDR sock[3]{};
          const nuint32_t addr = xhtonl(net::TruncateV6(ifaddr.range.addr));
          ip = net::TruncateV6(ifaddr.range.addr);
          m_Info.ifname = ip.ToString();
          const nuint32_t mask = xhtonl(net::TruncateV6(ifaddr.range.netmask_bits));
          LogInfo("address ", addr, " netmask ", mask);
          sock[0] = addr.n;
          sock[1] = addr.n & mask.n;
          sock[2] = mask.n;

          if (not DeviceIoControl(
                  m_Device,
                  TAP_IOCTL_CONFIG_TUN,
                  &sock,
                  sizeof(sock),
                  &sock,
                  sizeof(sock),
                  &len,
                  nullptr))
          {
            LogError("cannot set address");
            throw std::invalid_argument{"cannot configure tun interface address"};
          }

          IPADDR ep[4]{};

          ep[0] = addr.n;
          ep[1] = mask.n;
          ep[2] = (addr.n | ~mask.n) - htonl(1);
          ep[3] = 31536000;

          if (not DeviceIoControl(
                  m_Device,
                  TAP_IOCTL_CONFIG_DHCP_MASQ,
                  ep,
                  sizeof(ep),
                  ep,
                  sizeof(ep),
                  &len,
                  nullptr))
          {
            LogError("cannot set dhcp masq");
            throw std::invalid_argument{"Cannot configure tun interface dhcp"};
          }
#pragma pack(push)
#pragma pack(1)
          struct opt
          {
            uint8_t dhcp_opt;
            uint8_t length;
            uint32_t value;
          } dns, gateway;
#pragma pack(pop)

          const nuint32_t dnsaddr{xhtonl(m_Info.dnsaddr)};
          dns.dhcp_opt = 6;
          dns.length = 4;
          dns.value = dnsaddr.n;

          gateway.dhcp_opt = 3;
          gateway.length = 4;
          gateway.value = addr.n + htonl(1);

          if (not DeviceIoControl(
                  m_Device,
                  TAP_IOCTL_CONFIG_DHCP_SET_OPT,
                  &gateway,
                  sizeof(gateway),
                  &gateway,
                  sizeof(gateway),
                  &len,
                  nullptr))
          {
            LogError("cannot set gateway");
            throw std::invalid_argument{"cannot set tun gateway"};
          }

          if (not DeviceIoControl(
                  m_Device,
                  TAP_IOCTL_CONFIG_DHCP_SET_OPT,
                  &dns,
                  sizeof(dns),
                  &dns,
                  sizeof(dns),
                  &len,
                  nullptr))
          {
            LogError("cannot set dns");
            throw std::invalid_argument{"cannot set tun dns"};
          }
        }
      }
      // set ipv6 addresses
      for (const auto& ifaddr : m_Info.addrs)
      {
        if (ifaddr.fam == AF_INET6)
        {
          const auto maybe = GetInterfaceIndex(ip);
          if (maybe.has_value())
          {
            NetSH(
                "add address interface=" + std::to_string(*maybe) + " " + ifaddr.range.ToString());
          }
        }
      }
    }

    ~Win32Interface()
    {
      ULONG flag = 0;
      DWORD len;
      // put the interface down
      DeviceIoControl(
          m_Device,
          TAP_IOCTL_SET_MEDIA_STATUS,
          &flag,
          sizeof(flag),
          &flag,
          sizeof(flag),
          &len,
          nullptr);
      m_Run = false;
      CloseHandle(m_IOCP);
      // close the handle
      CloseHandle(m_Device);
      // close the reader threads
      for (auto& thread : m_Threads)
        thread.join();
    }

    int
    PollFD() const override
    {
      return -1;
    }

    std::string
    IfName() const override
    {
      return m_Info.ifname;
    }

    void
    Start()
    {
      m_Run = true;
      const auto numThreads = std::thread::hardware_concurrency();
      // allocate packets
      for (size_t idx = 0; idx < numThreads; ++idx)
        m_Packets.emplace_back(new asio_evt_pkt{true});

      // create completion port
      m_IOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
      // attach the handle or some shit
      CreateIoCompletionPort(m_Device, m_IOCP, 0, 0);
      // spawn reader threads
      for (size_t idx = 0; idx < numThreads; ++idx)
        m_Threads.emplace_back([this, idx]() { ReadLoop(idx); });
    }

    net::IPPacket
    ReadNextPacket() override
    {
      if (m_ReadQueue.empty())
        return net::IPPacket{};

      return m_ReadQueue.popFront();
    }

    struct asio_evt_pkt
    {
      explicit asio_evt_pkt(bool _read) : read{_read}
      {}

      OVERLAPPED hdr = {0, 0, 0, 0, nullptr};  // must be first, since this is part of the IO call
      bool read;
      net::IPPacket pkt;

      void
      Read(HANDLE dev)
      {
        ReadFile(dev, pkt.buf, sizeof(pkt.buf), nullptr, &hdr);
      }
    };

    std::vector<std::unique_ptr<asio_evt_pkt>> m_Packets;

    bool
    WritePacket(net::IPPacket pkt)
    {
      LogDebug("write packet ", pkt.sz);
      asio_evt_pkt* ev = new asio_evt_pkt{false};
      std::copy_n(pkt.buf, pkt.sz, ev->pkt.buf);
      ev->pkt.sz = pkt.sz;
      WriteFile(m_Device, ev->pkt.buf, ev->pkt.sz, nullptr, &ev->hdr);
      return true;
    }

    void
    ReadLoop(size_t packetIndex)
    {
      auto& ev = m_Packets[packetIndex];
      ev->Read(m_Device);
      while (m_Run)
      {
        DWORD size;
        ULONG_PTR user;
        OVERLAPPED* ovl = nullptr;
        if (not GetQueuedCompletionStatus(m_IOCP, &size, &user, &ovl, 1000))
          continue;
        asio_evt_pkt* pkt = (asio_evt_pkt*)ovl;
        LogDebug("got iocp event size=", size, " read=", pkt->read);
        if (pkt->read)
        {
          pkt->pkt.sz = size;
          m_ReadQueue.pushBack(pkt->pkt);
          pkt->Read(m_Device);
        }
        else
          delete pkt;
      }
    }
  };

  /// \brief FWPMRouterManager is heavily based off wireguard's windows port's firewall code
  class FWPMRouteManager : public IRouteManager
  {
    HANDLE m_Handle;

    template <typename Operation>
    void
    RunTransaction(Operation tx)
    {
      if (auto err = FwpmTransactionBegin0(m_Handle, 0); err != ERROR_SUCCESS)
      {
        throw std::runtime_error{"FwpmTransactionBegin0 failed"};
      }
      try
      {
        tx();
        if (auto err = FwpmTransactionCommit0(m_Handle); err != ERROR_SUCCESS)
        {
          throw std::runtime_error{"FwpmTransactionCommit0 failed"};
        }
      }
      catch (std::exception& ex)
      {
        LogError("failed to run fwpm transaction: ", ex.what());
        FwpmTransactionAbort0(m_Handle);
        throw std::current_exception();
      }
    }

    static void
    GenerateUUID(UUID& uuid)
    {
      if (auto err = UuidCreateSequential(&uuid); err != RPC_S_OK)
      {
        throw std::runtime_error{"cannot generate uuid"};
      }
    }

    class Provider
    {
      std::wstring _name;
      std::wstring _description;

     protected:
      FWPM_PROVIDER0 _provider;

     public:
      explicit Provider(const wchar_t* name, const wchar_t* description)
          : _name{name}, _description{description}
      {
        GenerateUUID(_provider.providerKey);
        _provider.displayData.name = _name.data();
        _provider.displayData.description = _description.data();
        _provider.flags = 0;
        _provider.serviceName = nullptr;
      }

      operator FWPM_PROVIDER0*()
      {
        return &_provider;
      }
    };

    class SubLayer
    {
      std::wstring _name;
      std::wstring _description;

     protected:
      FWPM_SUBLAYER0 _sublayer;

     public:
      explicit SubLayer(const wchar_t* name, const wchar_t* description, GUID* providerKey)
          : _name{name}, _description{description}
      {
        GenerateUUID(_sublayer.subLayerKey);
        _sublayer.providerKey = providerKey;
        _sublayer.displayData.name = _name.data();
        _sublayer.displayData.description = _description.data();
        _sublayer.weight = 0xffff;
      }

      operator FWPM_SUBLAYER0*()
      {
        return &_sublayer;
      }
    };

    class Firewall : public Provider, public SubLayer
    {
      HANDLE m_Handle;

     public:
      Firewall(HANDLE handle)
          : Provider{L"Lokinet", L"Lokinet Provider"}
          , SubLayer{L"Lokinet Filters", L"RoutePoker Filters", &_provider.providerKey}
          , m_Handle{handle}
      {
        if (auto err = FwpmProviderAdd0(m_Handle, *this, 0); err != ERROR_SUCCESS)
        {
          throw std::runtime_error{"fwpmProviderAdd0 failed"};
        }
        if (auto err = FwpmSubLayerAdd0(m_Handle, *this, 0); err != ERROR_SUCCESS)
        {
          throw std::runtime_error{"fwpmSubLayerAdd0 failed"};
        }
      }

      ~Firewall()
      {
        FwpmSubLayerDeleteByKey0(m_Handle, &_sublayer.subLayerKey);
        FwpmProviderDeleteByKey0(m_Handle, &_provider.providerKey);
      }
    };

    std::unique_ptr<Firewall> m_Firewall;

    void
    PermitLokinetService()
    {}

    void
    PermitLoopback()
    {}

    void
    PermitTunInterface()
    {}

   public:
    FWPMRouteManager()
    {
      if (auto result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &m_Handle);
          result != ERROR_SUCCESS)
      {
        throw std::runtime_error{"cannot open fwpm engine"};
      }
    }

    ~FWPMRouteManager()
    {
      FwpmEngineClose0(m_Handle);
    }

    void
    AddBlackhole() override
    {
      RunTransaction([&]() {
        m_Firewall = std::make_unique<Firewall>(m_Handle);
        PermitLokinetService();
        PermitLoopback();
      });
    }

    void
    DelBlackhole() override
    {
      RunTransaction([&]() { m_Firewall.reset(); });
    }

    void
    AddRoute(IPVariant_t ip, IPVariant_t gateway) override
    {}

    void
    DelRoute(IPVariant_t ip, IPVariant_t gateway) override
    {}

    void
    AddRouteViaInterface(NetworkInterface& vpn, IPRange range) override
    {}

    void
    DelRouteViaInterface(NetworkInterface& vpn, IPRange range) override
    {}

    std::vector<IPVariant_t>
    GetGatewaysNotOnInterface(std::string ifname) override
    {
      std::vector<IPVariant_t> gateways;
      ForEachWIN32Interface([&](auto w32interface) {
        struct in_addr gateway, interface_addr;
        gateway.S_un.S_addr = (u_long)w32interface->dwForwardDest;
        interface_addr.S_un.S_addr = (u_long)w32interface->dwForwardNextHop;
        std::string interface_name{inet_ntoa(interface_addr)};
        if ((!gateway.S_un.S_addr) and interface_name != ifname)
        {
          llarp::LogTrace(
              "Win32 find gateway: Adding gateway (", interface_name, ") to list of gateways.");
          huint32_t x{};
          if (x.FromString(interface_name))
            gateways.push_back(x);
        }
      });
      return gateways;
    }

    void
    AddDefaultRouteViaInterface(std::string ifname) override
    {}

    void
    DelDefaultRouteViaInterface(std::string ifname) override
    {}
  };

  class Win32Platform : public Platform
  {
    FWPMRouteManager _routeManager{};

   public:
    std::shared_ptr<NetworkInterface>
    ObtainInterface(InterfaceInfo info) override
    {
      auto netif = std::make_shared<Win32Interface>(std::move(info));
      netif->Start();
      return netif;
    };
    IRouteManager&
    RouteManager() override
    {
      return _routeManager;
    }
  };

}  // namespace llarp::vpn
