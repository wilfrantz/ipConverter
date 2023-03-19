/*
 * A class that represents an IP address and provides methods
 * for converting between different IP address formats, as well
 * as performing various operations related to IP addresses
 * Author: Wilfrantz Dede
 * Date: March 23
 */

#include "header.h"
#include "ipconverter.h"

namespace ipconverter
{
    class IPAddressConverter : public IPConverter
    {
    public:
        IPAddressConverter();
        ~IPAddressConverter() = default;
        void loadData(const std::string &ipAddr,
                      const std::string &ipVersion,
                      const std::string &ipClass = "",
                      const std::string &reverseDnsLookup = "",
                      const std::string &binaryConversion = "");

    private:
        typedef struct IPAddress
        {
            std::string _ipAddr;
            std::string _ipVersion;
            std::string _ipClass;
            std::string _reverseDnsLookup;
            std::string _binaryConversion;
        } IPAddress;
    };

} // end namespace ipconverter