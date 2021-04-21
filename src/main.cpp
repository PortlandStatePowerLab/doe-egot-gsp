#include "include/https_server.hpp"

int main(int argc, char* argv[])
{
    std::string address = "0.0.0.0";
    uint16_t port = 443;
    std::string doc_root = ".";
    HttpsServer gsp(address, port, doc_root);
    try
    {
        gsp.Run();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}