add_library(
    btc++
    bip39.cpp
    bip39.hpp
    bip39/types.hpp
    bip39/dictionary.cpp
    bip39/dictionary.hpp
    bip39/details.cpp
    bip39/details.hpp
    bip32.cpp
    bip32.hpp
    ec.hpp
    ec.cpp
    encoding.hpp
    encoding.cpp
    utils.cpp
    utils.hpp
    crypto.cpp
    crypto.hpp
)

target_link_libraries(btc++ PUBLIC PkgConfig::crypto++ PkgConfig::libsecp256k1 external::base58)
target_include_directories(btc++ PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include>)
