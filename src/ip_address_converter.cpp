#include <regex>
#include <boost/bind/bind.hpp>
#include <boost/asio/ts/socket.hpp>
#include <boost/regex.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/asio/ip/tcp.hpp>     // Header file for TCP support
#include <boost/asio/ip/address.hpp> // Header file for IP address support
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <idn2.h> // for idn::toASCII (optional, requires libidn)
#include <punycode.h>
#include "ip_address_converter.h"

using namespace boost::asio;
using namespace boost::asio::ip;
using namespace boost::asio::socket_errc;
namespace ipconverter
{
    IPAddressConverter::IPAddressConverter() {}
    IPAddressConverter::IPAddressConverter(const std::string &uid,
                                           const std::string &ipAddr,
                                           const std::string &operation)
        : _uid(uid), _ipAddr(ipAddr), _operation(operation)
    {
        dataMap["uid"] = uid;
        dataMap["operation"] = operation;
        getIpAttributes(_ipAddr);
    }

    /// @brief I am no longer sure about this function, will rework entirely.
    /// @param none
    /// @return none
    void IPAddressConverter::convert()
    {
    }

    /// @brief Get IP attributes
    /// @param ip_str IP address in string format.
    /// @return none.
    void IPAddressConverter::getIpAttributes(const std::string &ip_str)
    {
        spdlog::info("Getting IP attributes for: {}", ip_str);
        if (!ip_str.empty())
            _ipAddr = ip_str;
        if (!_ipAddr.empty())
        {
            if (isValidDomainName(_ipAddr))
            {
                try
                {
                    _ipAddr = boost::algorithm::join(convertToIPAddress(_ipAddr), ".");
                }
                catch (const boost::wrapexcept<boost::system::system_error> &ex)
                {
                    dataMap["error"] = dnsLookup(_ipAddr);
                    spdlog::error("DNS lookup failed: {}\n", dataMap["error"]);
                }
            }

            try
            {
                // boost::asio::ip::address address;
                address address = boost::asio::ip::make_address(_ipAddr);
                dataMap["version"] = address.is_v4() ? "IPv4" : "IPv6";

                if (dataMap["version"] == "IPv4")
                {
                    dataMap["class"] = getClass(address.to_v4());
                    dataMap["addrv4"] = address.to_v4().to_string();
                    dataMap["addrv6"] = convertToIPv6Mapped(address.to_v4()).to_string();
                }
                else
                {
                    dataMap["addrv6"] = address.to_v6().to_string();
                }

                dataMap["reverseDnsLookup"] = reverseDnsLookup(address);
                dataMap["binaryVersion"] = getBinaryRepresentation(address);
            }
            catch (std::exception &e)
            {
                spdlog::error("Invalid IP address: {}", _ipAddr);
                dataMap["error"] = "Invalid IP address";
            }
        }
        else
        {
            spdlog::error("IP address field is empty.");
            dataMap["error"] = "IP address field is empty.";
        }
        addToResults();
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
        // Split the input string into labels
        std::vector<std::string> labels;
        boost::split(labels, inputString, boost::is_any_of("."));

        // Check that the domain name has at least two labels
        if (labels.size() < 2)
        {
            return false;
        }

        // Check that each label is valid
        for (const auto &label : labels)
        {
            if (label.empty() || label.size() > 63)
            {
                return false;
            }
            if (!std::all_of(label.begin(), label.end(), [](char c)
                             { return std::isalnum(c) || c == '-' || c == '_'; }))
            {
                return false;
            }
            if (label.front() == '-' || label.back() == '-')
            {
                return false;
            }
        }

        // Check that the last label contains only letters
        const auto &lastLabel = labels.back();
        if (!std::all_of(lastLabel.begin(), lastLabel.end(), [](char c)
                         { return std::isalpha(c); }))
        {
            return false;
        }

        // The domain name is valid
        return true;
    }

    /// @brief get the binary representation of an IP address
    /// @param IP address
    /// @return binary representation of the IP address
    std::string IPAddressConverter::getBinaryRepresentation(const boost::asio::ip::address &address)
    {
        if (address.is_v4())
        {
            std::bitset<32> binary = address.to_v4().to_uint();
            return binary.to_string();
        }
        else
        {
            std::bitset<128> binary;
            // Handle IPv6 addresses
            auto ipv6_address = address.to_v6();

            // Check if the IPv6 address is an IPv4-mapped address
            if (ipv6_address.is_v4_mapped())
            {
                // Extract the IPv4 address from the IPv4-mapped IPv6 address
                auto ipv4_address = ipv6_address.to_v4().to_bytes();
                for (size_t i = 0; i < ipv4_address.size(); ++i)
                {
                    binary |= std::bitset<128>(ipv4_address[i]) << (120 - 8 * i);
                }
            }
            else
            {
                auto ipv6_address_bytes = ipv6_address.to_bytes();
                for (size_t i = 0; i < ipv6_address_bytes.size(); ++i)
                {
                    binary |= std::bitset<128>(ipv6_address_bytes[i]) << (120 - 8 * i);
                }
            }
            return binary.to_string();
        }

        return {};
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

    /// @brief Perform a DNS lookup for the given domain name and return the resolved IP address as a string.
    /// @param domain The domain name to perform a DNS lookup for.
    /// @return std::string The resolved IP address as a string if the lookup is successful, or "DNS lookup failed" if not.
    std::string IPAddressConverter::dnsLookup(const std::string &domain)
    {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);
        try
        {
            spdlog::info("Performing DNS lookup on {}", domain);
            boost::system::error_code ec;
            auto results = resolver.resolve(domain, "", ec);

            // if (ec || results == boost::asio::ip::tcp::resolver::iterator())
            if (ec)
            {
                spdlog::error("DNS lookup failed: {}", ec.message());
                return ec.message();
            }
            else
            {
                return results->endpoint().address().to_string();
            }
        }
        catch (const boost::wrapexcept<boost::system::system_error> &ex)
        {
            spdlog::error("DNS lookup failed with error: {}", ex.what());
            return "DNS lookup failed";
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
        try
        {
            spdlog::info("Performing reverse DNS lookup on {}", address.to_string());
            boost::system::error_code ec;
            auto results = resolver.resolve(boost::asio::ip::tcp::endpoint(address, 0), ec);

            if (ec || results == boost::asio::ip::tcp::resolver::iterator())
            {
                return "DNS lookup failed";
            }
            else
            {
                return results->host_name();
            }
        }
        catch (...)
        {
            return "DNS lookup failed";
        }
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
            tcp::resolver::results_type endpoints = resolver.resolve(hostname, "https");

            for (auto it = endpoints.begin(); it != endpoints.end(); ++it)
            {
                // ip_addresses.push_back(it->endpoint().address().to_string());
                if (it->endpoint().address().is_v4() || it->endpoint().address().is_v6())
                    ip_addresses.push_back(it->endpoint().address().to_string());
                else
                    ip_addresses.push_back("Invalid IP address");
            }

            return ip_addresses;
        }
        return {};
    }

    /// @brief Adds the results to the JSON file
    /// @param none.
    /// @return none.
    void IPAddressConverter::addToResults()
    {
        // Create a JSON object for this conversion
        Json::Value item(Json::objectValue);
        item["uid"] = dataMap["uid"];
        dataMap.erase("uid");
        item["operation"] = dataMap["operation"];
        dataMap.erase("operation");

        // Create a JSON array for the data
        Json::Value dataArray(Json::arrayValue);
        Json::Value dataItem(Json::objectValue);

        // add key-value pairs to data array
        for (const auto &kv : dataMap)
        {
            dataItem[kv.first] = kv.second;
        }
        dataArray.append(dataItem);

        // Add the data array to the item object
        item["data"] = dataArray;
        converter.addToResults(item);
    }

} // end namespace ipconverter