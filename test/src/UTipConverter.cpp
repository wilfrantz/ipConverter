#include "ipconverterMock.h"

#ifdef _WIN32 _WIN64
#endif

#ifdef linux
#else
#include <gtest/gtest.h>
#endif


TesT(UTipConverter, readUserInputMock) {
    ipconverter::IpConverterMock ipConverterMock;
    ipConverterMock.readUserInputMock();
    EXPECT_EQ(ipConverterMock._ipAddress);
}