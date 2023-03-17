#include "ipconverter.h"

namespace ipconverter {
class IpConverterMock : public IpConverter {
   public:
    IpConverterMock() {}

    void readUserInputMock();
    void displayResultsMock();

    ~IpConverterMock() = default;
};
}  // namespace ipconverter