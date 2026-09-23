cmake_minimum_required(VERSION 3.16)
project(wirevault-rpi-core
        VERSION 0.1.0
        DESCRIPTION "WireVault VPN vigilance control daemon"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)

if(WIN32)
  # Winsock for the control client/server on Windows (dev only)
  set(PLATFORM_LIBS ws2_32)
else()
  set(PLATFORM_LIBS)
endif()

add_library(wirevault_core STATIC
  src/config.cpp
  src/event_bus.cpp
  src/logging.cpp
  src/incident_store.cpp
  src/control_server.cpp
  src/ctl_client.cpp
  src/wireguard_mgr.cpp
  src/netfilter_mgr.cpp
  src/dnsfilter_mgr.cpp
  src/watch_elems.cpp
  src/subproc.cpp
)
target_include_directories(wirevault_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(wirevault_core PUBLIC SQLite::SQLite3 Threads::Threads ${PLATFORM_LIBS})

add_executable(wirevaultd src/main.cpp)
target_link_libraries(wirevaultd PRIVATE wirevault_core)

# command-line client for the control socket
add_executable(wvctl src/wvctl.cpp)
target_link_libraries(wvctl PRIVATE wirevault_core)

enable_testing()
add_executable(wirevault-tests tests/test_config.cpp)
target_include_directories(wirevault-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(wirevault-tests PRIVATE wirevault_core)
add_test(NAME config_tests COMMAND wirevault-tests)

add_executable(wirevault-incident-tests tests/test_incidents.cpp)
target_include_directories(wirevault-incident-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(wirevault-incident-tests PRIVATE wirevault_core)
add_test(NAME incident_tests COMMAND wirevault-incident-tests)
