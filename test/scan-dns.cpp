#include "scan_dns.h"
#include <catch2/catch.hpp>

TEST_CASE("Scan DNS")
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
    fty_proto_t* msg = fty_proto_new(FTY_PROTO_ASSET);
    fty_proto_ext_insert(msg, "ip.1", "%s", "127.0.0.1");
    scan_dns(msg, "127.0.0.1", NULL);
    fty_proto_print(msg);
    REQUIRE(fty_proto_ext_string(msg, "dns.1", NULL));
    REQUIRE(fty_proto_ext_string(msg, "hostname", NULL));
    fty_proto_destroy(&msg);
}
