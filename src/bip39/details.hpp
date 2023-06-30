#pragma once

#include <vector>
#include <string>

#include "bip39/types.hpp"

namespace btcpp::bip39::details {
std::vector<std::string> to_mnemonic(const Dictionary &dictionary, std::vector<uint8_t> entropy);
}

