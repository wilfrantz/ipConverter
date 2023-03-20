
#include "convert_address.h"
using namespace boost::asio;
using namespace boost::asio::ip;
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

    /// @brief  This method handles ip conversion and load
    /// ip attributes in struct.
    ///\param[in] none
    ///\return none.
    void IPAddressConverter::convert()
    {
        boost::asio::io_service io_service;

        spdlog::info("Converting IP address: {}", _ipAddr);
        if (ip._version == "v4")
        {
            if (!_ipAddr.empty())
            {
                address_v4 addr4 = make_address_v4(_ipAddr.c_str());
                ip._addrv4 = addr4.to_string();
            }
        }
        else if (ip._version == "v6")
        {
        }
        // ip::address_v6 addr6 = ip::address_v6::from_string(ip._addrv6);
        else
        {
        }
        // ip::address addr = ip::address::from_string(ip._binaryVersion);

        spdlog::info("IPv4 address in v6 form: {}", ip._addrv6);
        spdlog::info("IPv6 address in v4 form: {}", ip._addrv4);
    }
} // end namespace ipconverter