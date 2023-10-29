include(ExternalProject)

ExternalProject_Add(
    libbech32
    GIT_REPOSITORY https://github.com/sipa/bech32
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE ON
    BUILD_COMMAND ${CMAKE_CXX_COMPILER} -c -pie ref/c++/bech32.cpp ref/c++/segwit_addr.cpp
    COMMAND ${CMAKE_CXX_COMPILER_AR} rvs libbech32.a bech32.o segwit_addr.o
    INSTALL_COMMAND mkdir -p <INSTALL_DIR>/lib <INSTALL_DIR>/include
    COMMAND cp libbech32.a <INSTALL_DIR>/lib/
    COMMAND cp ref/c++/bech32.h ref/c++/segwit_addr.h <INSTALL_DIR>/include
)
ExternalProject_Get_Property(libbech32 INSTALL_DIR)
add_library(external::bech32 STATIC IMPORTED)
add_dependencies(external::bech32 libbech32)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include) # hack to make cmake happy
set_target_properties(
    external::bech32 PROPERTIES IMPORTED_LOCATION ${INSTALL_DIR}/lib/libbech32.a INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include
)
