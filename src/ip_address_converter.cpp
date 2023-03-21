#include <regex>
#include <boost/bind/bind.hpp>
#include <boost/asio/ts/socket.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/algorithm/string/join.hpp>

#include "ip_address_converter.h"

using namespace boost::asio;
using namespace boost::asio::ip;
using namespace boost::asio::socket_errc;
namespace ipconverter
{
    IPAddressConverter::IPAddressConverter() {}
    IPAddressConverter::IPAddressConverter(const std::string &ipAddr,
                                           const std::string &ipVersion,
                                           const std::string &ipClass,
                                           const std::string &reverseDnsLookup,
                                           const std::string &binaryVersion)
        : _ipAddr(ipAddr)
    {
        ip._version = ipVersion;
        ip._class = ipClass;
        ip._reverseDnsLookup = reverseDnsLookup;
        ip._binaryVersion = binaryVersion;

        convert();
    }

    void IPAddressConverter::convert()
    {
        boost::asio::io_service io_service;

        if (!_ipAddr.empty())
        {
            try
            {
                address_v4 addr4 = make_address_v4(_ipAddr.c_str());
                if (addr4.is_class_a())
                    ip._class = "A";
                else if (addr4.is_class_b())
                    ip._class = "B";
                else if (addr4.is_class_c())
                    ip._class = "C";
                else
                    ip._class = "D";
            }
            catch (std::exception &e)
            {
                try
                {
                    address_v6 addr6 = make_address_v6(_ipAddr.c_str());

                    if (addr6.is_v4_mapped())
                    {
                        ip._addrv4 = addr6.to_v4().to_string();
                        ip._version = "v4";
                    }
                    else
                    {
                        ip._addrv6 = addr6.to_string();
                        ip._version = "v6";
                    }
                }
                catch (std::exception &e)
                {
                    if (isBinary(_ipAddr))
                    {
                        ip._binaryVersion = _ipAddr;
                        ip._version = "binary";
                    }
                    else
                    {
                        if (isValidDomainName(_ipAddr))
                        {
                            _ipAddr = boost::algorithm::join(convertToIPAddress(_ipAddr), ".");

                            // ip._reverseDnsLookup = _ipAddr;
                            ip._version = "reverse dns";
                        }
                        else
                        {
                            // Log error and exit if necessary
                        }
                    }
                }
            }
        }
        else
        {
            // Log error and exit if necessary
        }

        // 93.184.216.34
        getIpAttributes(_ipAddr);

        /// TODO: Remove these spdlog::info() calls
        spdlog::info("IP Address: {}", _ipAddr);
        spdlog::info("IP Version: {}", ip._version);
        spdlog::info("IP Class: {}", ip._class);
        spdlog::info("IP Address v4: {}", ip._addrv4);
        spdlog::info("IP Address v6: {}", ip._addrv6);
        spdlog::info("IP Address Binary: {}", ip._binaryVersion);
        spdlog::info("IP Address Reverse DNS: {}", ip._reverseDnsLookup);
    }

    bool IPAddressConverter::isBinary(const std::string &inputString)
    {
        static const std::regex binaryRegex(R"(^(?:[01]{8}\.){3}[01]{8}$)");
        return std::regex_match(inputString, binaryRegex);
    }

    bool IPAddressConverter::isValidDomainName(const std::string &inputString)
    {
        static const std::regex domainNameRegex(R"(^(?=.{1,255}$)([a-zA-Z0-9][a-zA-Z0-9_-]{0,62}[a-zA-Z0-9]\.?)+[a-zA-Z]{2,}$)");
        return std::regex_match(inputString, domainNameRegex);
    }

    std::string IPAddressConverter::getBinaryRepresentation(const boost::asio::ip::address &address)
    {
        if (address.is_v4())
        {
            std::bitset<32> binary(address.to_v4().to_uint());
            return binary.to_string();
        }
        else
        {
            boost::asio::ip::address_v6::bytes_type bytes = address.to_v6().to_bytes();
            std::bitset<128> binary(*reinterpret_cast<unsigned long long *>(bytes.data()));
            return binary.to_string();
        }
    }

    std::string IPAddressConverter::getClass(const boost::asio::ip::address &address)
    {
        if (address.is_v4())
        {
            uint32_t addr = address.to_v4().to_uint();
            if ((addr & 0x80000000) == 0)
            {
                return "A";
            }
            else if ((addr & 0xC0000000) == 0x80000000)
            {
                return "B";
            }
            else if ((addr & 0xE0000000) == 0xC0000000)
            {
                return "C";
            }
            else if ((addr & 0xF0000000) == 0xE0000000)
            {
                return "D";
            }
            else
            {
                return "E";
            }
        }
        else
        {
            return "IPv6";
        }
    }

    std::string IPAddressConverter::reverseDnsLookup(const boost::asio::ip::address &address)
    {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);
        boost::system::error_code ec;
        auto results = resolver.resolve(boost::asio::ip::tcp::endpoint(address, 0), ec);

        if (ec)
        {
            return "Reverse DNS lookup failed";
        }
        else
        {
            return results->endpoint().address().to_string();
        }
    }

    void IPAddressConverter::getIpAttributes(const std::string &ip_str)
    {
        boost::system::error_code ec;
        address address = make_address(ip_str, ec);

        if (ec)
        {
            /// TODO: Log error and exit if necessary
            spdlog::error("Invalid IP address: {}", ip_str);
            return;
        }

        std::string version = address.is_v4() ? "IPv4" : "IPv6";
        std::string ip_class = "";
        if (version == "IPv4")
        {
            ip_class = getClass(address.to_v4());
        } // else{
          //  const address_v4 addrv4 = convertToIPv4(address);
        // }

        std::string binary_repr = getBinaryRepresentation(address);
        std::string reverse_dns = reverseDnsLookup(address);

        // std::cout << "IP address: " << ip_str << std::endl;
        // std::cout << "Version: " << version << std::endl;

        if (!ip_class.empty())
            ip._class = ip_class;

        ip._addrv4 = address.to_v4().to_string();
        ip._addrv6 = convertToIPv6Mapped(address.to_v4()).to_string();
        ip._version = version;
        ip._binaryVersion = binary_repr;
        ip._reverseDnsLookup = reverse_dns;
    }

    address_v6 IPAddressConverter::convertToIPv6Mapped(const address_v4 &ipv4_address)
    {
        return boost::asio::ip::address_v6::v4_mapped(ipv4_address);
    }

    address_v4 IPAddressConverter::convertToIPv4(const address_v6 &ipv6_address)
    {
        if (ipv6_address.is_v4_mapped())
        {
            return ipv6_address.to_v4();
        }
        else
        {
            throw std::runtime_error("IPv6 address is not an IPv4-mapped address");
        }
    }

    std::vector<std::string> IPAddressConverter::convertToIPAddress(const std::string &hostname)
    {
        if (isValidDomainName(hostname))
        {

            boost::asio::io_context io_context;
            tcp::resolver resolver(io_context);
            std::vector<std::string> ip_addresses;
            tcp::resolver::results_type endpoints = resolver.resolve(hostname, "http");

            for (auto it = endpoints.begin(); it != endpoints.end(); ++it)
            {
                ip_addresses.push_back(it->endpoint().address().to_string());
            }

            return ip_addresses;
        }
        return {};
    }

} // end namespace ipconverter