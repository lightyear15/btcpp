#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "bip32/types.hpp"

namespace btcpp::base58 {

std::vector<uint8_t> decode(const std::string &encoded, const std::string &prefix = {});
std::string encode(const std::span<uint8_t> &encoded, const std::string &prefix = {});

} // namespace btcpp::base58
