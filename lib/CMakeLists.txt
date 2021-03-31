cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

##############################################################################################################

etn_target(static ${PROJECT_NAME}-static
    SOURCES
        src/assets.cc
        src/cidr.cc
        src/device_scan.cc
        src/range_scan.cc
        src/scan_dns.cc
        src/scan_nut.cc
    PUBLIC_INCLUDE_DIR
        public_includes
    INCLUDE_DIRS
        include
    USES
        czmq
        cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
        fty-asset-accessor
        fty_common
        fty_common_db
        fty_common_logging
        fty_common_nut
        fty_proto
        fty_security_wallet
        fty-utils
        mlm
        tntdb
    PRIVATE
)


##############################################################################################################
