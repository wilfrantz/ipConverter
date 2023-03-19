
#include "header.h"
#include "ipconverter.h"

namespace ipconverter
{

    // NOTE: Methods for handling user input and output.
    void IPConverter::readUserInput()
    {
        // spdlog::info("Welcome to spdlog!");
        std::cout << "Enter an IP address or domain name: ";
        std::cin >> this->_ipAddress;
    }

    void IPConverter::displayResults()
    {
        std::cout << "IP address: " << this->_ipAddress << std::endl;
    }

    /// TODO: For coordinating the interactions between other classes.
    void IPConverter::convertIPAddress() {}
    void IPConverter::performGeolocationLookup() {}
    void IPConverter::performReverseDNSLookup() {}
    void IPConverter::calculateIPAddressRange() {}
    void IPConverter::calculateCIDRNotation() {}
    void IPConverter::performWhoisLookup() {}
    void IPConverter::scanIPAddressRange() {}
    void IPConverter::performBlacklistCheck() {}
    void IPConverter::convertIPType() {}
    void IPConverter::convertDecimalToBinary() {}
    void IPConverter::supportCIDRNotation() {}
    void IPConverter::identifyNetworkClass() {}
    void IPConverter::calculateSubnetting() {}
    void IPConverter::performDNSLookup() {}
    void IPConverter::performMACAddressLookup() {}

} // namespace ipconverter
