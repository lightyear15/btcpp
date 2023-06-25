cmake_minimum_required(VERSION 3.18)

project(btcpp)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


#dependencies
find_package(Boost COMPONENTS random headers REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(crypto++ REQUIRED IMPORTED_TARGET libcrypto++)

add_subdirectory(src)
add_subdirectory(test)
