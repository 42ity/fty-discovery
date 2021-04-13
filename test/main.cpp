#define CATCH_CONFIG_RUNNER

#include <catch2/catch.hpp>

int main(int argc, char** argv)
{
    Catch::Session session;

    int returnCode = session.applyCommandLine(argc, argv);
    if (returnCode != 0) {
        return returnCode;
    }

    int result = session.run(argc, argv);
    return result;
}
