/*
 * A class that represents an IP address and provides methods
 * for converting between different IP address formats, as well
 * as performing various operations related to IP addresses
 * Author: Wilfrantz Dede
 * Date: March 23, 20xx
 */
#ifndef IP_ADDRESS_CONVERTER_H
#define IP_ADDRESS_CONVERTER_H
#include "header.h"
#include "ipconverter.h"

namespace ipconverter
{
    class IPAddressConverter : public IPConverter
    {
    public:
        IPAddressConverter();
        IPAddressConverter(const std::string &ipAddr,
                           const std::string &ipVersion,
                           const std::string &ipClass = "",
                           const std::string &reverseDnsLookup = "",
                           const std::string &binaryConversion = "");

        void convert();
        bool isBinary(const std::string &ipAddr);
        bool isValidDomainName(const std::string& inputString);

        ~IPAddressConverter() = default;

    private:
        std::string _ipAddr;
        typedef struct IPAddress
        {
            std::string _class{};
            std::string _addrv4{};
            std::string _addrv6{};
            std::string _version{};
            std::string _binaryVersion{};
            std::string _reverseDnsLookup{};
        } IPAddressAttributes;

        IPAddressAttributes ip;
    };

} // end namespace ipconverter
#endif // IP_ADDRESS_CONVERTER_H