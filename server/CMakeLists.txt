cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

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
        fty-asset-accessor
        fty_common
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

configure_file(fty-discovery.service.in
  "${PROJECT_BINARY_DIR}/fty-discovery.service" @ONLY)

install(FILES
  "${PROJECT_BINARY_DIR}/fty-discovery.service"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/systemd/system/"
)

#install config file

configure_file(conf/fty-discovery.cfg.in
  "${PROJECT_BINARY_DIR}/fty-discovery.cfg" @ONLY)

install(FILES
  "${PROJECT_BINARY_DIR}/fty-discovery.cfg"
  DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/fty-discovery/"
)

##############################################################################################################

if(BUILD_TESTING)
    enable_testing()

    # Create a target for the tests
    etn_test(${PROJECT_NAME}-test
        SOURCES
            src/fty_discovery_server.cc
            test/fty_discovery_selftest.cc
            test/fty_discovery_private_selftest.cc
        USES
            ${PROJECT_NAME}-static
            cidr
            czmq
            cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
            fty-asset-accessor
            fty_common
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
    
endif()
