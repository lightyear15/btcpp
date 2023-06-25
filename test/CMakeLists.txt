
enable_testing()

find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(bip39
    bip39.cpp
)
target_link_libraries(bip39
    PRIVATE
        btc++
        GTest::GTest
        GTest::Main
        Boost::headers
)
target_include_directories(bip39 PRIVATE ${CMAKE_SOURCE_DIR}/src)

gtest_discover_tests(bip39)
