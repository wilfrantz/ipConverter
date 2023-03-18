#include "ipconverter_mock.h"

namespace ipconverter
{
    IpConverterMock::IpConverterMock() {}

    void IpConverterMock::readUserInputMock() { IPConverter::readUserInput(); }

    void IpConverterMock::displayResultsMock() { IPConverter::displayResults(); }
} // namespace ipconverter