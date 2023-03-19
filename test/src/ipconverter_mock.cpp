#include "ipconverter_mock.h"

namespace ipconverter
{
    IpConverterMock::IpConverterMock() {}

    void IpConverterMock::readUserInputMock(const char* jsonFile) { IPConverter::readUserInput(jsonFile); }

    void IpConverterMock::displayResultsMock() { IPConverter::displayResults(); }
} // namespace ipconverter