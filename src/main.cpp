/***************************************************************
 * Name: ipconverter.cpp
 * Author: Wilfrantz Dede
 * Date: March 23, 20xx
 * Description: Command-line interface for the IPConverter.com web app
 * ************************************************************/

#include "ip_converter.h"

int main(int argc, char *argv[])
{
    spdlog::info("Starting IPConverter\n");
    if (argc == 1)
    {
        ipconverter::IPConverter ipConverter;
        ipConverter.readUserInput(std::cin);
        ipConverter.displayResults();
    }
    else
        return 1;
    return 0;
}
