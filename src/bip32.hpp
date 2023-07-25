#pragma once

#include "bip39.hpp"

namespace btcpp::bip32 {

using MasterSecretKey = std::array<uint8_t,32>;
using ChainCode = std::array<uint8_t,32>;
struct MasterKey {
    MasterSecretKey secret;
    ChainCode chain_code;
};

const std::string MASTERKEY_KEY = "Bitcoin seed";
const std::string MASTERKEY_PREFIX = "xpriv";
MasterKey to_master_key(const bip39::Seed &seed);
} // namespace btcpp::bip32
