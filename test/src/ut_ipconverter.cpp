#include "ipconverter_mock.h"

#ifdef _WIN64
#endif

#ifdef linux
#else
#include <gtest/gtest.h>
#endif

TEST(UTipConverter, readUserInputMock)
{
    std::string ipAddress = "dede";
    ipconverter::IpConverterMock ipConverterMock;
    ipConverterMock.readUserInputMock();

    // EXPECT_STREQ(ipConverterMock._ipAddress, ipAddress);
}