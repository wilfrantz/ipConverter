
/* The main class that provides the core functionality of the program. This
 * class will be responsible for handling user input and output, as well as
 * coordinating the interactions between other classes.
 * Author: Wilfrantz Dede
 * Date: March 23 */

#ifndef IP_CONVERTER_H
#define IP_CONVERTER_H

#include <iostream>
#include <string>


// #include "spdlog/spdlog.h"

namespace ipconverter
{

   class IPConverter
   {
   public:
      IPConverter() {}
      ~IPConverter() = default;

      // NOTE: Methods for handling user input and output.
      void readUserInput();
      void displayResults();

      /// NOTE: Other methods for coordinating the interactions between other
      /// classes.
      void convertIPAddress();
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

   private:
      // For storing user input and other data.
      std::string _ipAddress;
      std::string _subnetMask;
      std::string _startingIPAddress;
      std::string _endingIPAddress;
      std::string _domainName;
      int _portNumber;
      bool _isIPAddress;

      friend class IPConverterTest;
   };

} // end namespace ipconverter

#endif // IP_CONVERTER_H