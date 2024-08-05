#pragma once

#include <span>
#include <string>
#include <vector>

#include "bip39/types.hpp"

namespace btcpp::bip39::details {
std::vector<std::string> to_mnemonic(const Dictionary &dictionary, std::span<const uint8_t> entropy);
void generate(std::span<uint8_t> entropy);
} // namespace btcpp::bip39::details
