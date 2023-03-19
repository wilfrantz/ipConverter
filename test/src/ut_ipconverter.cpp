#include "ipconverter_mock.h"

#ifdef _WIN64
#endif

#ifdef linux
#else
#include <gtest/gtest.h>
#endif

TEST(UTipConverter, readUserInputMock)
{
    const char *jsonFile = "test.json";
    std::string ipAddress = "dede";
    ipconverter::IpConverterMock ipConverterMock;
    ipConverterMock.readUserInputMock(jsonFile);

    // EXPECT_STREQ(ipConverterMock._ipAddress, ipAddress);
}