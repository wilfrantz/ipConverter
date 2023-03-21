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

    /// @brief I am no longer sure about this function, will rework entirely.
    /// @param none
    /// @return none
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

        /// TODO: WIll improve this later
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

    /// @brief Check if the input string is a valid binary IP address
    /// @param inputString
    /// @return true if the input string is a valid binary IP address, false otherwise
    bool IPAddressConverter::isBinary(const std::string &inputString)
    {
        static const std::regex binaryRegex(R"(^(?:[01]{8}\.){3}[01]{8}$)");
        return std::regex_match(inputString, binaryRegex);
    }

    /// @brief Check if the input string is a valid domain name
    /// @param inputString
    /// @return true if the input string is a valid domain name, false otherwise
    bool IPAddressConverter::isValidDomainName(const std::string &inputString)
    {
        static const std::regex domainNameRegex(R"(^(?=.{1,255}$)([a-zA-Z0-9][a-zA-Z0-9_-]{0,62}[a-zA-Z0-9]\.?)+[a-zA-Z]{2,}$)");
        return std::regex_match(inputString, domainNameRegex);
    }

    /// @brief get the binary representation of an IP address
    /// @param IP address
    /// @return binary representation of the IP address
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

    /// @brief Get the class attribute of the IP address
    /// @param IP address
    /// @return class aatribute
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

    /// TODO:
    /// @brief Convert  IP adrress to domain name
    /// @param IP address
    /// @return domain name
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

    /// @brief Get IP attributes
    /// @param ip_str IP address in string format.
    /// @return none.
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

        if (!ip_class.empty())
            ip._class = ip_class;

        ip._addrv4 = address.to_v4().to_string();
        ip._addrv6 = convertToIPv6Mapped(address.to_v4()).to_string();
        ip._version = version;
        ip._binaryVersion = binary_repr;
        ip._reverseDnsLookup = reverse_dns;
    }

    /// @brief  Converts an IPv4 address to an IPv6-mapped address
    /// @param ipv4_address The IPv4 address to convert
    /// @return The IPv6-mapped address
    address_v6 IPAddressConverter::convertToIPv6Mapped(const address_v4 &ipv4_address)
    {
        return boost::asio::ip::address_v6::v4_mapped(ipv4_address);
    }

    /// @brief Converts an IPv6-mapped address to an IPv4 address
    /// @param ipv6_address The IPv6-mapped address to convert
    /// @return The IPv4 address
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

    /// @brief Converts a domain name to an IP address
    /// @param hostname The domain name to convert
    /// @return A vector of IP addresses
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