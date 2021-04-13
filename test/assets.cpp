#include "assets.h"
#include <catch2/catch.hpp>

TEST_CASE("Assets")
{
    //  @selftest
    assets_t* self = assets_new();
    REQUIRE(self);

    fty_proto_t* msg = fty_proto_new(FTY_PROTO_ASSET);
    fty_proto_set_name(msg, "%s", "ups");
    fty_proto_set_operation(msg, "%s", "create");
    fty_proto_aux_insert(msg, "type", "%s", "device");
    fty_proto_aux_insert(msg, "subtype", "%s", "ups");
    fty_proto_ext_insert(msg, "ip.1", "%s", "127.0.0.1");
    fty_proto_ext_insert(msg, "ip.2", "%s", "127.0.0.2");
    fty_proto_ext_insert(msg, "name", "%s", "my-nice-name");
    assets_put(self, &msg);

    REQUIRE(assets_find(self, "name", "my-nice-name"));
    REQUIRE(assets_find(self, "name", "bad name") == NULL);
    REQUIRE(assets_find(self, "ip", "127.0.0.1"));
    REQUIRE(assets_find(self, "ip", "127.0.0.2"));
    REQUIRE(assets_find(self, "ip", "127.0.0.3") == NULL);
    assets_destroy(&self);
}
