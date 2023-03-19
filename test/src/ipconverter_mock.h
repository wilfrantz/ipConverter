#include "ipconverter.h"

namespace ipconverter
{
    class IpConverterMock : public IPConverter
    {
    public:
        IpConverterMock();

        void readUserInputMock(const char* jsonFile);
        void displayResultsMock();

        ~IpConverterMock() = default;
    };

} // namespace ipconverter