#include <map>

#include "header.h"
#include "ip_converter.h"
#include "ip_address_converter.h"

namespace ipconverter
{

    /* @brief Read user input from a given input stream, parse
     * it as JSON, and perform the specified operations.
     *
     * This method reads the input stream and parses it as a
     * JSON object containing an array of operations.
     * Each operation must have a unique identifier (uid) and a type.
     * Based on the operation type, the method
     * calls the appropriate function to perform the desired task, such
     * as converting IP addresses, performing
     * DNS lookups, or calculating CIDR notations.
     *
     * @param[in] input - std::istream object: The input stream containing
     * the JSON data to parse and process.
     */
    void IPConverter::readUserInput(std::istream &input)
    {
        spdlog::info("[readUserInput()]: Loading data from stdin.\n");
        Json::Value root;
        input >> root;

        // Iterate through root array to filter by operation.
        for (unsigned int index = 0; index < root.size(); index++)
        {
            const auto &uid = root[index].get("uid", "").asString();
            const auto &operation = root[index].get("operation", "").asString();

            switch (metricTypeMap[operation])
            {
            case metricType::IP_ADDRESS_CONVERSION:
                convertIPAddress(uid, root[index]);
                break;
            case metricType::DOMAIN_NAME:
                performDNSLookup();
                break;
            case metricType::IP_ADDRESS_RANGE:
                calculateIPAddressRange();
                break;
            case metricType::CIDR_NOTATION:
                calculateCIDRNotation();
                break;
            case metricType::MAC_ADDRESS:
                performMACAddressLookup();
                break;
            case metricType::IP_TYPE:
                convertIPType();
                break;
            case metricType::IP_VERSION:
                convertIPAddress(uid, root[index]);
                break;
            case metricType::IP_CLASS:
                identifyNetworkClass();
                break;
            case metricType::SUBNET_MASK:
                calculateSubnetting();
                break;
            case metricType::SUBNETTING:
                calculateSubnetting();
                break;
            case metricType::DNS_LOOKUP:
                performDNSLookup();
                break;
            case metricType::WHOIS_LOOKUP:
                performWhoisLookup();
                break;
            case metricType::BLACKLIST_CHECK:
                performBlacklistCheck();
                break;
            case metricType::GEOLOCATION_LOOKUP:
                performGeolocationLookup();
                break;
            case metricType::REVERSE_DNS_LOOKUP:
                performReverseDNSLookup();
                break;
            case metricType::PORT_SCAN:
                scanIPAddressRange();
                break;
            case metricType::BINARY_CONVERSION:
                convertDecimalToBinary();
                break;
            case metricType::CIDR_SUPPORT:
                supportCIDRNotation();
                break;
            default:
                spdlog::error("Invalid operation type: {}", operation);
                break;
            }
        }
    }

    void IPConverter::addToResults() {}

    void IPConverter::displayResults() {}

    /// @brief Convert IP addresses from a JSON object and instantiate
    /// IPAddressConverter objects for each IP address.
    /// @param uid A unique identifier for the conversion process.
    /// @param root The JSON object containing the IP addresses and optional fields.
    void IPConverter::convertIPAddress(const std::string &uid, Json::Value root)
    {
        spdlog::info("[Operation]: {}.", root["operation"].asString());
        const unsigned int dataSize = root["data"].size();
        for (unsigned int index = 0; index < dataSize; ++index)
        {
            const std::string &ipAddress(root["data"][index]["ip_address"].asString());
            // Optional fields.
            const std::string &ipClass(root["data"][index].get("class", "").asString());
            const std::string &binary(root["data"][index].get("binary", "").asString());
            const std::string &version(root["data"][index].get("version", "").asString());
            const std::string &reverseDns(root["data"][index].get("reverseDns", "").asString());

            spdlog::info("Processing: {}\n", ipAddress);
            IPAddressConverter converter(uid, ipAddress, version, ipClass, reverseDns, binary);
        }
    }

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
