
#include "convert_address.h"

namespace ipconverter
{
    IPAddressConverter::IPAddressConverter() {}

    /// @brief  This method reads data from user.
    ///\param[in] root - Json::Value object: root object.
    ///\return none.
    void IPAddressConverter::loadData(const std::string &ipAddr,
                                      const std::string &ipVersion,
                                      const std::string &ipClass,
                                      const std::string &reverseDnsLookup,
                                      const std::string &binaryConversion)
    {
        IPAddress ip;
        ip._ipAddr = ipAddr;
        ip._ipVersion = ipVersion;
        ip._ipClass = ipClass;
        ip._reverseDnsLookup = reverseDnsLookup;
        ip._binaryConversion = binaryConversion;

        std::cout << " ipAddress: " << ip._ipAddr << "\n"
                  << " ipVersion: " << ip._ipVersion << "\n"
                  << " ipClass: " << ip._ipClass << "\n"
                  << " reverseDnsLookup: " << ip._reverseDnsLookup << "\n"
                  << " binaryConversion: " << ip._binaryConversion << "\n"
                  << std::endl;
    }
} // end namespace ipconverter