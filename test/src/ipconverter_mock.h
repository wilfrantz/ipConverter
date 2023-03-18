#include "ipconverter.h"

namespace ipconverter
{
    class IpConverterMock : public IPConverter
    {
    public:
        IpConverterMock();

        void readUserInputMock();
        void displayResultsMock();

        ~IpConverterMock() = default;
    };

} // namespace ipconverter