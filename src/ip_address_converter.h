/*
 * A class that represents an IP address and provides methods
 * for converting between different IP address formats, as well
 * as performing various operations related to IP addresses
 * Author: Wilfrantz Dede
 * Date: March 23, 20xx
 */
#ifndef IP_ADDRESS_CONVERTER_H
#define IP_ADDRESS_CONVERTER_H

#include <string>
#include "header.h"
#include "ip_converter.h"

using namespace boost::asio::ip;

namespace ipconverter
{
    class IPAddressConverter : public IPConverter
    {
    public:
        IPAddressConverter();
        IPConverter converter;
        IPAddressConverter(const std::string &uid,
                           const std::string &ipAddr,
                           const std::string &operation);

        void convert();
        void addToResults();
        bool isBinary(const std::string &ipAddr);
        std::string dnsLookup(const std::string &domain);
        void getIpAttributes(const std::string &ip_str = "");
        std::string reverseDnsLookup(const address &address);
        bool isValidDomainName(const std::string &inputString);
        address_v4 convertToIPv4(const address_v6 &ipv6_address);
        std::string getBinaryRepresentation(const address &address);
        std::string getClass(const boost::asio::ip::address &address);
        address_v6 convertToIPv6Mapped(const address_v4 &ipv4_address);
        std::vector<std::string> convertToIPAddress(const std::string &hostname);

        ~IPAddressConverter() = default;

    private:
        std::string _uid{};
        std::string _ipAddr{};
        std::string _operation{};
        std::map<std::string, std::string> dataMap;
    };

} // end namespace ipconverter
#endif // IP_ADDRESS_CONVERTER_H