
add_library(btc++ 
    bip39.cpp bip39.hpp
    bip39/types.hpp
    bip39/dictionary.cpp bip39/dictionary.hpp
    bip39/details.cpp bip39/details.hpp
    utils.cpp utils.hpp
)

target_link_libraries(btc++ PUBLIC
    PkgConfig::crypto++
)
target_include_directories(btc++ PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
