#include "fty_discovery_server.h"
#include <catch2/catch.hpp>

TEST_CASE("Discovery Server")
{
    //  @selftest
    //  Simple create/destroy test
    zactor_t* self = zactor_new(fty_discovery_server, NULL);
    REQUIRE(self);
    zclock_sleep(500);
    zactor_destroy(&self);
}
