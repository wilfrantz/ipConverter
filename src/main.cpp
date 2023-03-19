#include <fstream>
#include <iostream>
#include "ipconverter.h"

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        ipconverter::IPConverter ipConverter;
        ipConverter.readUserInput(std::cin);
        ipConverter.displayResults();
    }
    else
    {
        std::cout << "Usage: " << argv[0] << std::endl;
        return 1;
    }

    return 0;
}
