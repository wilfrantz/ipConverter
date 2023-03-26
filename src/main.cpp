/****************************************************************
 * Name: ipConverter.com
 * Author: Wilfrantz Dede
 * Date: March 23, 20xx
 * Description: backend Interface of the IPConverter.com web app
 * *************************************************************/

#include "ip_converter.h"

int main(int argc, char *argv[])
{
    ipconverter::IPConverter ipConverter;
    spdlog::info("IPConverter: {}.\n", ipConverter.getVersion());
    if (argc == 1)
    {
        ipConverter.readUserInput(std::cin);
        ipConverter.displayResults();
    }
    else
        return 1;
    return 0;
}
