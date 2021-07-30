#include "range_scan.h"
#include <catch2/catch.hpp>

TEST_CASE("Range scan")
{
    //  Simple create/destroy test
    range_scan_t* self = range_scan_new("127.0.0.0/24");
    REQUIRE(self);
    REQUIRE(self->size == 256);
    self->cursor = 128;
    REQUIRE(range_scan_progress(self) == 50);
    range_scan_destroy(&self);
}
