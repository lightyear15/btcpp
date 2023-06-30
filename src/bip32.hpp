#pragma once

#include "bip32/types.hpp"
#include "bip39/types.hpp"

namespace btcpp::bip32 {

const std::string MASTERKEY_KEY = "Bitcoin seed";
const std::string MASTERKEY_PREFIX = "xpriv";
MasterKey to_master_key(const bip39::Seed &seed);
} // namespace btcpp::bip32
