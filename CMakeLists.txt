cmake_minimum_required(VERSION 3.18)

project(btcpp)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


#dependencies
include(ExternalProject)
ExternalProject_Add(libbase58
    GIT_REPOSITORY https://github.com/bitcoin/libbase58
    GIT_TAG v0.1.4
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND <SOURCE_DIR>/autogen.sh
    COMMAND <SOURCE_DIR>/configure --with-pic --disable-shared --prefix <INSTALL_DIR>
    BUILD_COMMAND make
    INSTALL_COMMAND make install
)
ExternalProject_Get_Property(libbase58 INSTALL_DIR)
add_library(external::base58 STATIC IMPORTED)
add_dependencies(external::base58 libbase58)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include) # hack to make cmake happy
set_target_properties(external::base58 PROPERTIES
    IMPORTED_LOCATION ${INSTALL_DIR}/lib/libbase58.a
    INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include
)
find_package(Boost COMPONENTS random headers REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(crypto++ REQUIRED IMPORTED_TARGET libcrypto++)



add_subdirectory(src)
add_subdirectory(test)
