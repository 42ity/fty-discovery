#include "device_scan.h"
#include <catch2/catch.hpp>

TEST_CASE("Device Scan")
{
    //  @selftest
    //  Simple create/destroy test

    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase (asert) to make compilers happy.
    const char* SELFTEST_DIR_RO = "src/selftest-ro";
    const char* SELFTEST_DIR_RW = "src/selftest-rw";
    REQUIRE(SELFTEST_DIR_RO);
    REQUIRE(SELFTEST_DIR_RW);
    // Uncomment these to use C++ strings in C++ selftest code:
    // std::string str_SELFTEST_DIR_RO = std::string(SELFTEST_DIR_RO);
    // std::string str_SELFTEST_DIR_RW = std::string(SELFTEST_DIR_RW);
    // REQUIRE ( (str_SELFTEST_DIR_RO != "") );
    // REQUIRE ( (str_SELFTEST_DIR_RW != "") );
    // NOTE that for "char*" context you need (str_SELFTEST_DIR_RO + "/myfilename").c_str()

    zactor_t* self = device_scan_new(nullptr, nullptr, nullptr, nullptr);
    REQUIRE(self);

    // zconfig /etc/default/fty.cfg
    // snmp
    //    community
    //        0 = "public"
    zconfig_t* cfg = zconfig_new("root", NULL);
    zconfig_put(cfg, "/snmp/community/0", "public");
    zconfig_put(cfg, "/snmp/community/1", "private");

    // TODO
    // zmsg_t *msg = device_scan_scan ("10.231.107.40", cfg, NULL);
    // zmsg_destroy (&msg);

    zconfig_destroy(&cfg);
    zactor_destroy(&self);
}
