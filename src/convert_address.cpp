
#include <regex>
#include <boost/asio/ts/socket.hpp>
#include "convert_address.h"

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

    /// @brief  responsible for handling the conversion of IP
    /// addresses and loading the resulting attributes into a struct.
    ///\param[in] none
    ///\return none.
    void IPAddressConverter::convert()
    {
        boost::asio::io_service io_service;

        spdlog::info("Converting IP address: {}", _ipAddr);
        if (!_ipAddr.empty()) 
        {
            try
            { // Check if IP address is valid.
                spdlog::info("Checking if {} is valid IPv4.", _ipAddr);
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
                spdlog::error("{} is not a valid v4 address.", _ipAddr);

                try
                {
                    spdlog::info("Checking if {} is valid IPv6.", _ipAddr);
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
                    spdlog::error("{} is not a valid v6 address.", _ipAddr);

                    if (isBinary(_ipAddr))
                    {
                        ip._binaryVersion = _ipAddr;
                        ip._version = "binary";
                    }
                    else
                    {
                        spdlog::error("{} is not a valid binary address.", _ipAddr);
                        spdlog::info("Checking if {} is valid reverse DNS.", _ipAddr);
                        /// TODO: check if it is a reverse DNS lookup.
                        if (isValidDomainName(_ipAddr))
                        {
                            spdlog::info("{} is valid reverse DNS.", _ipAddr);
                            ip._reverseDnsLookup = _ipAddr;
                            ip._version = "reverse dns";
                        }
                        else
                        {
                            spdlog::error("{} is not a valid reverse DNS address.", _ipAddr);
                            exit(-1); // TODO: log error and exit.
                        }
                    }

                }
            }
        }
        else
        {
            spdlog::error("IP address field is empty.");
            exit(-1); // TODO: log error and exit.
        }

        spdlog::info("IPv4 address in v6 form: {}", ip._addrv6);
        spdlog::info("IPv6 address in v4 form: {}", ip._addrv4);
        spdlog::info("IP address class: {}", ip._class);
        spdlog::info("IP address version: {}", ip._version);
        spdlog::info("IP address binary version: {}", ip._binaryVersion);
        spdlog::info("IP address reverse DNS lookup: {}", ip._reverseDnsLookup);
    }

    /// @brief  checks if a string is a binary string.
    ///\param[in] string to be checked.
    ///\return true if string is a binary string, false otherwise.
    bool IPAddressConverter::isBinary(const std::string &inputString)
    {
        spdlog::info("Checking if {} is a binary string.", inputString);
        static const std::regex binaryRegex(R"(^(?:[01]{8}\.){3}[01]{8}$)");
        return std::regex_match(inputString, binaryRegex);
    }

    /// @brief checks if a string is a valid domain name.
    ///\param[in] string to be checked.
    ///\return true if string is a valid domain name, false otherwise.
    bool IPAddressConverter::isValidDomainName(const std::string &inputString)
    {
        static const std::regex domainNameRegex(R"(^(?=.{1,255}$)([a-zA-Z0-9][a-zA-Z0-9_-]{0,62}[a-zA-Z0-9]\.?)+[a-zA-Z]{2,}$)");
        return std::regex_match(inputString, domainNameRegex);
    }

} // end namespace ipconverter