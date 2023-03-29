
/* The main class that provides the core functionality of the program. This
 * class will be responsible for handling user input and output, as well as
 * coordinating the interactions between other classes.
 * @Author: Wilfrantz Dede
 * @Date: March 23, 20xx */

#ifndef IP_CONVERTER_H
#define IP_CONVERTER_H

#include "header.h"

// #include "spdlog/spdlog.h"

namespace ipconverter
{
   class IPConverter
   {
   public:
      IPConverter()
      {
         _logger = spdlog::get("console");
         if (!_logger)
         {
            _logger = spdlog::stdout_color_mt("console");
         }
      }
      std::string getVersion() const { return this->_version; }

      void displayResults();
      void addToResults(Json::Value &item);
      void readUserInput(std::istream &input);
      std::string getFile() const { return this->_filePath; }

      enum metricType
      {
         IP_ADDRESS_CONVERSION,
         DOMAIN_NAME,
         IP_ADDRESS_RANGE,
         CIDR_NOTATION,
         MAC_ADDRESS,
         IP_TYPE,
         IP_VERSION,
         IP_CLASS,
         SUBNET_MASK,
         SUBNETTING,
         DNS_LOOKUP,
         WHOIS_LOOKUP,
         BLACKLIST_CHECK,
         GEOLOCATION_LOOKUP,
         REVERSE_DNS_LOOKUP,
         PORT_SCAN,
         BINARY_CONVERSION,
         CIDR_SUPPORT,
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
      void convertIPAddress(const std::string &uid,
                            const Json::Value &root,
                            const std::string &opeartion);

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

   protected:
      static std::vector<Json::Value> _results;

   private:
      std::string _version = "v1.0.0";
      std::string _dirName = "results";
      std::string _filename = "results.json";
      static std::shared_ptr<spdlog::logger> _logger;
      std::filesystem::path _path = std::filesystem::current_path();
      const std::string _filePath = (_path / _dirName / _filename).string();

      int _portNumber;
      bool _isIPAddress;
      std::string _subnetMask;
      std::string _startingIPAddress;
      std::string _endingIPAddress;
      std::string _domainName;

#ifdef UNIT_TEST
      friend class IPConverterTest;
#endif
   };

} // end namespace ipconverter

#endif // IP_CONVERTER_H