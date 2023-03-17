#include "ipconverterMock.h"

namespace ipconverter {
IpConverterMock::IpConverterMock() { IpConverter::IpConverter(); }

void IpConverterMock::readUserInputMock() { IpConverter::readUserInput(); }

void IpConverterMock::displayResultsMock() { IpConverter::displayResults(); }
}  // namespace ipconverter