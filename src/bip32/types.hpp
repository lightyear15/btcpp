#pragma once

#include <array>
#include <cstdint>
#include <utility>


namespace btcpp::bip32 {

using MasterSecretKey = std::array<uint8_t,32>;
using ChainCode = std::array<uint8_t,32>;
struct MasterKey {
    MasterSecretKey secret;
    ChainCode chain_code;
};

} // namespace btcpp::bip32
