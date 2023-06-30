
enable_testing()

find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(bips
    data/testvectors.cpp
    bip39.cpp
    bip32.cpp
    encoding.cpp
)

target_link_libraries(bips
    PRIVATE
        btc++
        GTest::GTest
        GTest::Main
        Boost::headers
)
target_include_directories(bips PRIVATE ${CMAKE_SOURCE_DIR}/src)

gtest_discover_tests(bips)
