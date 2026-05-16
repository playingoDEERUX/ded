#pragma once
#include <string>
#include <enet/enet.h>

struct IPAddress {
    char ip[16] = { 0 };

    inline std::string GetAsString() const noexcept
    {
        return std::string(ip);
    }

    inline enet_uint32 GetAsInt() const noexcept
    {
        ENetAddress addr;
        enet_address_set_host_ip(&addr, ip);

        return addr.host;
    }

    inline IPAddress(const enet_uint32 ipv4)
    {
        Set(ipv4);
    }

    inline const bool SetFromStr(const std::string& ip)
    {
        ENetAddress addr;

        if (enet_address_set_host_ip(&addr, ip.c_str()) == 0)
        {
            Set(addr.host);
            return true;
        }

        return false;
    }

    inline const bool SetFromDomain(const std::string& domain)
    {
        ENetAddress addr;

        if (enet_address_set_host(&addr, domain.c_str()) == 0)
        {
            Set(addr.host);
            return true;
        }

        return false;
    }

    inline void Set(int ipv4)
    {
        ENetAddress addr;
        addr.host = ipv4;

        enet_address_get_host_ip(&addr, ip, 16);
    }
};