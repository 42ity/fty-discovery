cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-discovery
    VERSION 1.0.0
    DESCRIPTION "42ity service for discovering devices"
)

##############################################################################################################
find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)
##############################################################################################################


##############################################################################################################
etn_target(static ${PROJECT_NAME}-static
    SOURCES
        src/assets.cc
        src/cidr.cc
        src/device_scan.cc
        src/range_scan.cc
        src/scan_dns.cc
        src/scan_nut.cc
    USES
        czmq
        cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
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
etn_target(exe ${PROJECT_NAME}-server
    SOURCES
        src/fty_discovery_server.cc
        src/fty_discovery.cc
    USES
        ${PROJECT_NAME}-static
        cidr
        czmq
        cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
        fty_common_db
        fty_common_logging
        fty_common_nut
        fty_common_socket
        fty_proto
        fty_security_wallet
        fty-utils
        mlm
        tntdb
)

#install systemd config

etn_configure_file( 
    src/fty-discovery.service.in
    TARGET ${PROJECT_NAME}-server
    DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/systemd/system/"
)

#install config file

etn_configure_file( 
    src/conf/fty-discovery.cfg.in    
    TARGET ${PROJECT_NAME}-server
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/fty-discovery/"
)

##############################################################################################################

etn_test_target(${PROJECT_NAME}-server
    SOURCES
        test/main.cpp
        test/assets.cpp
        test/cidr.cpp
        test/device-scan.cpp
        test/fty-discovery-server.cpp
        test/range-scan.cpp
        test/scan-dns.cpp
        test/scan-nut.cpp
        src/fty_discovery_server.cc
    PUBLIC_INCLUDE_DIR
        src
)

##############################################################################################################
