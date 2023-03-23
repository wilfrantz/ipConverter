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
        IPAddressConverter(const std::string &uid,
                           const std::string &ipAddr,
                           const std::string &ipVersion,
                           const std::string &ipClass = "",
                           const std::string &reverseDnsLookup = "",
                           const std::string &binaryConversion = "");

        void convert();
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
        typedef struct IpInfo
        {
            std::string _class{};
            std::string _addrv4{};
            std::string _addrv6{};
            std::string _version{};
            std::string _dnsLookUp{};
            std::string _binaryVersion{};
            std::string _reverseDnsLookup{};
        } IpInfo;

        IpInfo ip;
        std::string _uid{};
        std::string _ipAddr{};
    };

} // end namespace ipconverter
#endif // IP_ADDRESS_CONVERTER_H

/*
#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <hostname>\n";
        return 1;
    }

    boost::asio::io_context io_context;
    tcp::resolver resolver(io_context);
    tcp::resolver::results_type endpoints = resolver.resolve(argv[1], "http");

    for (auto it = endpoints.begin(); it != endpoints.end(); ++it) {
        std::cout << it->endpoint().address().to_string() << std::endl;
    }

    return 0;
}

*/