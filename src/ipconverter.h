
/* The main class that provides the core functionality of the program. This
 * class will be responsible for handling user input and output, as well as
 * coordinating the interactions between other classes.
 * @Author: Wilfrantz Dede
 * @Date: March 23 */

#ifndef IP_CONVERTER_H
#define IP_CONVERTER_H

#include "header.h"

// #include "spdlog/spdlog.h"

namespace ipconverter
{

   class IPConverter
   {
   public:
      IPConverter() {}

      std::string getVersion() const { return this->_version; }

      // NOTE: Methods for handling user input and output.
      void readUserInput(std::istream& input);
      void displayResults();
      // fill the result object.
      void addToResults();

        enum metricType
        {
            IP_ADDRESS_CONVERSION = 1,
            DOMAIN_NAME = 2,
            IP_ADDRESS_RANGE = 3,
            CIDR_NOTATION = 4,
            MAC_ADDRESS = 5,
            IP_TYPE = 6,
            IP_VERSION = 7,
            IP_CLASS = 8,
            SUBNET_MASK = 9,
            SUBNETTING = 10,
            DNS_LOOKUP = 11,
            WHOIS_LOOKUP = 12,
            BLACKLIST_CHECK = 13,
            GEOLOCATION_LOOKUP = 14,
            REVERSE_DNS_LOOKUP = 15,
            PORT_SCAN = 16,
            BINARY_CONVERSION = 17,
            CIDR_SUPPORT = 18,
        };

        std::map<std::string, metricType> metricTypeMap = {
            {"IP_ADDRESS_CONVERSION", metricType::IP_ADDRESS_CONVERSION},
            {"DOMAIN_NAME", metricType::DOMAIN_NAME},
            {"IP_ADDRESS_RANGE", metricType::IP_ADDRESS_RANGE},
            {"CIDR_NOTATION", metricType::CIDR_NOTATION},
            {"MAC_ADDRESS", metricType::MAC_ADDRESS},
            {"IP_TYPE", metricType::IP_TYPE},
            {"IP_VERSION", metricType::IP_VERSION},
            {"IP_CLASS", metricType::IP_CLASS},
            {"SUBNET_MASK", metricType::SUBNET_MASK},
            {"SUBNETTING", metricType::SUBNETTING},
            {"DNS_LOOKUP", metricType::DNS_LOOKUP},
            {"WHOIS_LOOKUP", metricType::WHOIS_LOOKUP},
            {"BLACKLIST_CHECK", metricType::BLACKLIST_CHECK},
            {"GEOLOCATION_LOOKUP", metricType::GEOLOCATION_LOOKUP},
            {"REVERSE_DNS_LOOKUP", metricType::REVERSE_DNS_LOOKUP},
            {"PORT_SCAN", metricType::PORT_SCAN},
            {"BINARY_CONVERSION", metricType::BINARY_CONVERSION},
            {"CIDR_SUPPORT", metricType::CIDR_SUPPORT}};


      /// NOTE: Methods for coordinating the interactions other classes
      // void coordinator(Json::Value root, const std::string &operation);
        void convertIPAddress(Json::Value root);
        void performGeolocationLookup();
        void performReverseDNSLookup();
        void calculateIPAddressRange();
        void calculateCIDRNotation();
        void performWhoisLookup();
        void scanIPAddressRange();
        void performBlacklistCheck();
        void convertIPType();
        void convertDecimalToBinary();
        void supportCIDRNotation();
        void identifyNetworkClass();
        void calculateSubnetting();
        void performDNSLookup();
        void performMACAddressLookup();

        ~IPConverter() = default;

     private:
        // For storing user input and other data.
        std::string _version = "v1.0.0";
        std::string _subnetMask;
        std::string _startingIPAddress;
        std::string _endingIPAddress;
        std::string _domainName;
        int _portNumber;
        bool _isIPAddress;

#ifdef UNIT_TEST
      friend class IPConverterTest;
#endif
   };
} // end namespace ipconverter

#endif // IP_CONVERTER_H